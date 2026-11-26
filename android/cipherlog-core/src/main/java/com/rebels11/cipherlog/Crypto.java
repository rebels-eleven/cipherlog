package com.rebels11.cipherlog;

import com.google.crypto.tink.InsecureSecretKeyAccess;
import com.google.crypto.tink.aead.internal.InsecureNonceChaCha20Poly1305;
import com.google.crypto.tink.hybrid.HpkeParameters;
import com.google.crypto.tink.hybrid.HpkePrivateKey;
import com.google.crypto.tink.hybrid.HpkePublicKey;
import com.google.crypto.tink.hybrid.internal.HpkeDecrypt;
import com.google.crypto.tink.hybrid.internal.HpkeEncrypt;
import com.google.crypto.tink.subtle.X25519;
import com.google.crypto.tink.util.Bytes;
import com.google.crypto.tink.util.SecretBytes;
import java.security.GeneralSecurityException;

/**
 * Every use of Tink, and nothing else. No other class of the library names a Tink type, so an app that left Tink out
 * (or has a Tink whose internal classes changed) loads the library fine; the first call in here then throws a
 * {@link LinkageError}, which the writer turns into {@code cipherlog off: crypto unavailable (...)}.
 *
 * <p>Tink classes from {@code internal} packages carry no compatibility promise: the version is pinned (1.24.0) and the
 * vectors are the check before raising it.
 */
final class Crypto {
    private Crypto() {
    }

    /** ChaCha20-Poly1305 (RFC 8439) with a caller-chosen nonce, for records. */
    interface RecordCipher {
        byte[] seal(byte[] nonce, byte[] plain, byte[] aad) throws GeneralSecurityException;

        byte[] open(byte[] nonce, byte[] sealed, byte[] aad) throws GeneralSecurityException;
    }

    static RecordCipher recordCipher(byte[] key) throws GeneralSecurityException {
        return new TinkRecordCipher(key);
    }

    /** HPKE base mode seal (DHKEM X25519 / HKDF-SHA256 / ChaCha20-Poly1305): {@code enc ‖ ciphertext ‖ tag}. */
    static byte[] hpkeSeal(byte[] publicKey, byte[] plain, byte[] info) throws GeneralSecurityException {
        HpkePublicKey key = HpkePublicKey.create(Params.HPKE, Bytes.copyFrom(publicKey), null);
        return HpkeEncrypt.create(key).encrypt(plain, info);
    }

    /** Opens {@code enc ‖ ciphertext ‖ tag} with a raw X25519 private key. */
    static byte[] hpkeOpen(byte[] privateKey, byte[] encAndSealed, byte[] info) throws GeneralSecurityException {
        HpkePublicKey publicKey =
                HpkePublicKey.create(Params.HPKE, Bytes.copyFrom(X25519.publicFromPrivate(privateKey)), null);
        HpkePrivateKey secret =
                HpkePrivateKey.create(publicKey, SecretBytes.copyFrom(privateKey, InsecureSecretKeyAccess.get()));
        return HpkeDecrypt.create(secret).decrypt(encAndSealed, info);
    }

    static byte[] publicFromPrivate(byte[] privateKey) throws GeneralSecurityException {
        return X25519.publicFromPrivate(privateKey);
    }

    /** Built on first use, so loading {@link Crypto} needs no Tink class. */
    private static final class Params {
        static final HpkeParameters HPKE = build();

        private static HpkeParameters build() {
            try {
                return HpkeParameters.builder()
                        .setKemId(HpkeParameters.KemId.DHKEM_X25519_HKDF_SHA256)
                        .setKdfId(HpkeParameters.KdfId.HKDF_SHA256)
                        .setAeadId(HpkeParameters.AeadId.CHACHA20_POLY1305)
                        .setVariant(HpkeParameters.Variant.NO_PREFIX)
                        .build();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("HPKE parameters", e);
            }
        }
    }

    private static final class TinkRecordCipher implements RecordCipher {
        private final InsecureNonceChaCha20Poly1305 aead;

        TinkRecordCipher(byte[] key) throws GeneralSecurityException {
            aead = new InsecureNonceChaCha20Poly1305(key);
        }

        @Override
        public byte[] seal(byte[] nonce, byte[] plain, byte[] aad) throws GeneralSecurityException {
            return aead.encrypt(nonce, plain, aad);
        }

        @Override
        public byte[] open(byte[] nonce, byte[] sealed, byte[] aad) throws GeneralSecurityException {
            return aead.decrypt(nonce, sealed, aad);
        }
    }
}
