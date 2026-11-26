//! cipherlog-v1 binary format: keys, header (HPKE), records, bundle, inflate. SPEC.md sections 1, 2, 4.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use flate2::{Decompress, FlushDecompress, Status};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MAGIC: &[u8; 4] = b"CPL1";
pub const BUNDLE_MAGIC: &[u8; 4] = b"CPB1";
pub const HEADER_LEN: usize = 118;
pub const RECORD_HEADER_LEN: usize = 9;
pub const MIN_RECORD_LEN: u32 = 16;
pub const MAX_RECORD_LEN: u32 = 65_552;
pub const MAX_RECORD_PLAINTEXT: usize = MAX_RECORD_LEN as usize - 16;
pub const INFLATE_CAP: usize = 64 * 1024 * 1024;
/// SPEC.md 5.4: all files of one read call (one `cipherlog open`) together.
pub const TOTAL_INFLATE_CAP: usize = 256 * 1024 * 1024;
pub const FLAG_FINAL: u8 = 0x01;
/// Largest integer a JavaScript number holds exactly; readers reject a later `createdAt`.
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const KEY_LABEL: &[u8] = b"cipherlog-key-v1";
const INFO_LABEL: &[u8] = b"cipherlog-v1";
const REC_LABEL: &[u8] = b"cipherlog-rec-v1";

/// An error of the format layer (bad input to an encoder, a header that does not open, a failed RNG).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatError(pub String);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for FormatError {}

fn err<T>(m: impl Into<String>) -> Result<T, FormatError> {
    Err(FormatError(m.into()))
}

pub fn hex(b: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(D[(x >> 4) as usize] as char);
        s.push(D[(x & 15) as usize] as char);
    }
    s
}

/// Lower- or uppercase hex to bytes; `None` for an odd length or a non-hex character.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    b.chunks(2).map(|p| Some(v(p[0])? << 4 | v(p[1])?)).collect()
}

/// Cryptographically secure random bytes from the operating system.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], FormatError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| FormatError(format!("random: {e}")))?;
    Ok(b)
}

// ---------- keys ----------

/// First 8 bytes of SHA-256("cipherlog-key-v1" ‖ publicKey).
pub fn key_id_of(public_key: &[u8; 32]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(KEY_LABEL);
    h.update(public_key);
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

type PrivateKeyX = <X25519HkdfSha256 as Kem>::PrivateKey;
type PublicKeyX = <X25519HkdfSha256 as Kem>::PublicKey;
type EncappedKeyX = <X25519HkdfSha256 as Kem>::EncappedKey;

fn private_key_object(raw: &[u8; 32]) -> Result<PrivateKeyX, FormatError> {
    PrivateKeyX::from_bytes(raw).map_err(|_| FormatError("bad private key".into()))
}

pub fn public_key_from_private(private_key: &[u8; 32]) -> Result<[u8; 32], FormatError> {
    let sk = private_key_object(private_key)?;
    let pk = X25519HkdfSha256::sk_to_pk(&sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.to_bytes());
    Ok(out)
}

/// A key pair; the private half is wiped when dropped.
pub struct KeyPair {
    pub public_key: [u8; 32],
    pub private_key: Zeroizing<[u8; 32]>,
    pub key_id: [u8; 8],
}

pub fn generate_key_pair() -> KeyPair {
    let (sk, pk) = X25519HkdfSha256::gen_keypair();
    let mut skb = sk.to_bytes();
    let mut private_key = Zeroizing::new([0u8; 32]);
    private_key.copy_from_slice(&skb);
    skb.zeroize();
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&pk.to_bytes());
    KeyPair { key_id: key_id_of(&public_key), public_key, private_key }
}

// ---------- HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305 ----------

/// HPKE single-shot seal (base mode). Returns `enc` (32 bytes) and the ciphertext with its tag.
pub fn hpke_seal(recipient_public_key: &[u8; 32], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<([u8; 32], Vec<u8>), FormatError> {
    let pk = PublicKeyX::from_bytes(recipient_public_key).map_err(|_| FormatError("bad public key".into()))?;
    let (enc, ct) = hpke::single_shot_seal::<HpkeChaCha, HkdfSha256, X25519HkdfSha256>(&OpModeS::Base, &pk, info, pt, aad)
        .map_err(|e| FormatError(format!("HPKE seal: {e}")))?;
    let mut e = [0u8; 32];
    e.copy_from_slice(&enc.to_bytes());
    Ok((e, ct))
}

/// HPKE single-shot open (base mode).
pub fn hpke_open(
    recipient_private_key: &[u8; 32],
    enc: &[u8],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let sk = private_key_object(recipient_private_key)?;
    let enc = EncappedKeyX::from_bytes(enc).map_err(|_| FormatError("bad encapsulated key".into()))?;
    hpke::single_shot_open::<HpkeChaCha, HkdfSha256, X25519HkdfSha256>(&OpModeR::Base, &sk, &enc, info, ct, aad)
        .map(Zeroizing::new)
        .map_err(|_| FormatError("authentication failed".into()))
}

// ---------- header ----------

/// The decrypted header. `file_key` is wiped when dropped.
pub struct HeaderInfo {
    pub key_id: [u8; 8],
    pub file_key: Zeroizing<[u8; 32]>,
    pub file_id: [u8; 16],
    pub created_at: u64,
    pub platform: u8,
    pub process: u8,
}

pub fn header_info_bytes(key_id: &[u8; 8]) -> Vec<u8> {
    [INFO_LABEL, MAGIC, key_id].concat()
}

pub fn encode_header(
    public_key: &[u8; 32],
    file_key: &[u8; 32],
    file_id: &[u8; 16],
    created_at: u64,
    platform: u8,
    process: u8,
) -> Result<Vec<u8>, FormatError> {
    if created_at > MAX_SAFE_INTEGER {
        return err("bad createdAt");
    }
    let key_id = key_id_of(public_key);
    let mut pt = Zeroizing::new(Vec::with_capacity(58));
    pt.extend_from_slice(file_key);
    pt.extend_from_slice(file_id);
    pt.extend_from_slice(&created_at.to_be_bytes());
    pt.push(platform);
    pt.push(process);
    let (enc, ct) = hpke_seal(public_key, &header_info_bytes(&key_id), &[], &pt)?;
    let out = [MAGIC.as_slice(), &key_id, &enc, &ct].concat();
    if out.len() != HEADER_LEN {
        return err(format!("header length {}", out.len()));
    }
    Ok(out)
}

/// Magic and keyId, the only clear parts of a header.
pub fn peek_header(buf: &[u8]) -> Result<[u8; 8], FormatError> {
    if buf.len() < HEADER_LEN {
        return err("shorter than a header");
    }
    if &buf[..4] != MAGIC {
        return err("not a cipherlog file (magic)");
    }
    let mut k = [0u8; 8];
    k.copy_from_slice(&buf[4..12]);
    Ok(k)
}

pub fn open_header(buf: &[u8], private_key: &[u8; 32]) -> Result<HeaderInfo, FormatError> {
    let key_id = peek_header(buf)?;
    let pt = hpke_open(private_key, &buf[12..44], &header_info_bytes(&key_id), &[], &buf[44..HEADER_LEN])
        .map_err(|_| FormatError("header does not open (HPKE)".into()))?;
    if pt.len() != 58 {
        return err(format!("header plaintext length {}", pt.len()));
    }
    let created_at = u64::from_be_bytes(pt[48..56].try_into().unwrap());
    if created_at > MAX_SAFE_INTEGER {
        return err("createdAt out of range");
    }
    let mut file_key = Zeroizing::new([0u8; 32]);
    file_key.copy_from_slice(&pt[..32]);
    let mut file_id = [0u8; 16];
    file_id.copy_from_slice(&pt[32..48]);
    Ok(HeaderInfo { key_id, file_key, file_id, created_at, platform: pt[56], process: pt[57] })
}

// ---------- records ----------

fn record_nonce(seq: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[8..].copy_from_slice(&seq.to_be_bytes());
    Nonce::from(n)
}

fn record_aad(file_id: &[u8; 16], len: u32, seq: u32, flags: u8) -> Vec<u8> {
    [REC_LABEL, file_id, &len.to_be_bytes(), &seq.to_be_bytes(), &[flags]].concat()
}

pub fn encrypt_record(file_key: &[u8; 32], file_id: &[u8; 16], seq: u32, flags: u8, plaintext: &[u8]) -> Result<Vec<u8>, FormatError> {
    if plaintext.len() > MAX_RECORD_PLAINTEXT {
        return err("record plaintext over 64 KiB");
    }
    if flags & !FLAG_FINAL != 0 {
        return err("reserved flag bits");
    }
    let len = plaintext.len() as u32 + 16;
    let aad = record_aad(file_id, len, seq, flags);
    let c = ChaCha20Poly1305::new(file_key.into());
    let ct = c.encrypt(&record_nonce(seq), Payload { msg: plaintext, aad: &aad }).map_err(|_| FormatError("record seal failed".into()))?;
    let mut out = Vec::with_capacity(RECORD_HEADER_LEN + ct.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(flags);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Why a record was rejected; `reason` is the exact text of SPEC.md 5.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    pub reason: String,
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}
impl std::error::Error for RecordError {}

fn rec_err<T>(reason: impl Into<String>) -> Result<T, RecordError> {
    Err(RecordError { reason: reason.into() })
}

pub struct DecodedRecord {
    pub seq: u32,
    pub flags: u8,
    pub plaintext: Vec<u8>,
    /// Bytes the record takes in the file, header included.
    pub size: usize,
}

/// Decodes the record at `offset`, checking in the order of SPEC.md 5.3: length bounds, truncated, seq, flags, AEAD.
pub fn decrypt_record(
    file_key: &[u8; 32],
    file_id: &[u8; 16],
    expected_seq: u32,
    buf: &[u8],
    offset: usize,
) -> Result<DecodedRecord, RecordError> {
    let rest = buf.len().saturating_sub(offset);
    if rest < RECORD_HEADER_LEN {
        return rec_err("truncated");
    }
    let b = &buf[offset..];
    let len = u32::from_be_bytes(b[0..4].try_into().unwrap());
    let seq = u32::from_be_bytes(b[4..8].try_into().unwrap());
    let flags = b[8];
    if !(MIN_RECORD_LEN..=MAX_RECORD_LEN).contains(&len) {
        return rec_err(format!("bad length {len}"));
    }
    let size = RECORD_HEADER_LEN + len as usize;
    if rest < size {
        return rec_err("truncated");
    }
    if seq != expected_seq {
        return rec_err(format!("seq {seq}, expected {expected_seq}"));
    }
    if flags & !FLAG_FINAL != 0 {
        return rec_err(format!("reserved flag bits 0x{flags:02x}"));
    }
    let aad = record_aad(file_id, len, seq, flags);
    let c = ChaCha20Poly1305::new(file_key.into());
    match c.decrypt(&record_nonce(seq), Payload { msg: &b[RECORD_HEADER_LEN..size], aad: &aad }) {
        Ok(plaintext) => Ok(DecodedRecord { seq, flags, plaintext, size }),
        Err(_) => rec_err("authentication failed"),
    }
}

// ---------- compression ----------

pub struct InflateResult {
    pub text: Vec<u8>,
    pub note: Option<String>,
}

/// SPEC.md 5.4: a compressed stream that breaks keeps the text before the damage.
pub const DAMAGED_NOTE: &str = "compressed stream damaged, text kept up to the damage";
pub const CAPPED_NOTE: &str = "output capped at 64 MiB";

const INFLATE_CHUNK: usize = 64 * 1024;

/// Inflates one raw deflate stream, accepting an unfinished one, with at most `cap` bytes of output.
///
/// The stream is decoded incrementally, so the text before a cut or damage is kept exactly (the output chunk is never
/// smaller than the 32 KiB window, so nothing decoded before an error is held back inside the decoder). Past `cap`
/// the output is cut at exactly `cap` bytes with `cap_note`. Bytes after the end of the stream are ignored.
pub fn inflate_stream(compressed: &[u8], cap: usize, cap_note: &str) -> InflateResult {
    let mut text = Vec::new();
    if compressed.is_empty() {
        return InflateResult { text, note: None };
    }
    let mut d = Decompress::new(false);
    let mut buf = vec![0u8; INFLATE_CHUNK];
    loop {
        let in_pos = d.total_in() as usize;
        let room = cap - text.len();
        if room == 0 {
            // Is there more output past the cap?
            let mut probe = [0u8; 1];
            let before = d.total_out();
            return match d.decompress(&compressed[in_pos..], &mut probe, FlushDecompress::None) {
                Ok(_) if d.total_out() > before => InflateResult { text, note: Some(cap_note.to_string()) },
                Ok(_) => InflateResult { text, note: None },
                Err(_) => InflateResult { text, note: Some(DAMAGED_NOTE.to_string()) },
            };
        }
        let n = room.min(INFLATE_CHUNK);
        let (before_in, before_out) = (d.total_in(), d.total_out());
        let r = d.decompress(&compressed[in_pos..], &mut buf[..n], FlushDecompress::None);
        let produced = (d.total_out() - before_out) as usize;
        text.extend_from_slice(&buf[..produced]);
        match r {
            Err(_) => return InflateResult { text, note: Some(DAMAGED_NOTE.to_string()) },
            Ok(Status::StreamEnd) => return InflateResult { text, note: None },
            Ok(_) => {
                if produced == 0 && d.total_in() == before_in {
                    // No progress: the input ends inside an unfinished stream.
                    return InflateResult { text, note: None };
                }
            }
        }
    }
}

// ---------- bundle ----------

pub fn encode_bundle<B: AsRef<[u8]>>(files: &[B]) -> Vec<u8> {
    let mut out = BUNDLE_MAGIC.to_vec();
    for f in files {
        let f = f.as_ref();
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

pub fn is_bundle(buf: &[u8]) -> bool {
    buf.len() >= 4 && &buf[..4] == BUNDLE_MAGIC
}

pub struct DecodedBundle<'a> {
    pub files: Vec<&'a [u8]>,
    pub note: Option<String>,
}

pub fn decode_bundle(buf: &[u8]) -> DecodedBundle<'_> {
    if !is_bundle(buf) {
        return DecodedBundle { files: vec![], note: Some("not a cipherlog bundle (magic)".into()) };
    }
    let mut files = Vec::new();
    let mut off = 4;
    while off < buf.len() {
        let len = if buf.len() - off < 4 { None } else { Some(u32::from_be_bytes(buf[off..off + 4].try_into().unwrap()) as usize) };
        let Some(len) = len.filter(|&l| l <= buf.len() - off - 4) else {
            let note = format!("bad length at entry {}, bundle ends", files.len() + 1);
            return DecodedBundle { files, note: Some(note) };
        };
        files.push(&buf[off + 4..off + 4 + len]);
        off += 4 + len;
    }
    DecodedBundle { files, note: None }
}
