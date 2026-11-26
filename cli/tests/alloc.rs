// Memory behaviour that only an allocator can see: freed blocks that still hold the private key, and the peak memory of
// opening a hostile file. One test function, so no other test thread allocates while it measures.
mod common;

use cipherlog::cli::{Input, key_file_json, load_key, op_item_template, write_report};
use cipherlog::format::unhex;
use cipherlog::keys::private_key_string;
use cipherlog::reader::{KeyRing, ReadBudget};
use common::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::os::unix::fs::PermissionsExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// The system allocator, plus: when `ARMED`, every freed block is searched for `NEEDLE` (16 hex characters of the test
/// private key), and the live and peak byte counts are kept. `realloc` is the trait's default (alloc, copy, dealloc),
/// so a block left behind by a growing buffer is searched too.
struct Watch;

static ARMED: AtomicBool = AtomicBool::new(false);
static NEEDLE: OnceLock<[u8; 16]> = OnceLock::new();
static LEAKS: AtomicUsize = AtomicUsize::new(0);
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(live, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst)
            && let Some(needle) = NEEDLE.get()
        {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(needle.len()).any(|w| w == needle) {
                LEAKS.fetch_add(1, Ordering::SeqCst);
            }
        }
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Watch = Watch;

/// Freed blocks holding the key while `f` runs (`f` drops everything it makes).
fn leaks_during(f: impl FnOnce()) -> usize {
    LEAKS.store(0, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    f();
    ARMED.store(false, Ordering::SeqCst);
    LEAKS.load(Ordering::SeqCst)
}

/// Peak bytes above the live bytes at the start, while `f` runs.
fn peak_during(f: impl FnOnce()) -> usize {
    let base = LIVE.load(Ordering::SeqCst);
    PEAK.store(base, Ordering::SeqCst);
    f();
    PEAK.load(Ordering::SeqCst) - base
}

#[test]
fn private_key_copies_are_wiped_and_a_hostile_file_costs_bounded_memory() {
    let k = test_key();
    let private: [u8; 32] = unhex(&k.private_hex).unwrap().try_into().unwrap();
    let public = pub_key();
    NEEDLE.set(k.private_hex.as_bytes()[..16].try_into().unwrap()).unwrap();

    // keygen --out: the key file JSON; keygen --op-vault: the 1Password item.
    assert_eq!(leaks_during(|| drop(key_file_json(&public, &private))), 0, "key_file_json leaves a copy of the key");
    assert_eq!(leaks_during(|| drop(private_key_string(&private))), 0, "private_key_string leaves a copy");
    let item = leaks_during(|| {
        let s = private_key_string(&private);
        drop(op_item_template("cipherlog key", &s, "cipherlog-pub-v1:00", "0011223344556677"));
    });
    assert_eq!(item, 0, "op_item_template leaves a copy of the key");

    // open --key op://…: what `op read` prints is read into one buffer, never a growing one.
    let dir = tmp_dir("alloc-op");
    let op = dir.join("op");
    std::fs::write(&op, format!("#!/bin/sh\nprintf '%s\\n' 'cipherlog-priv-v1:{}'\n", k.private_hex)).unwrap();
    std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:/usr/bin:/bin", dir.display());
    // SAFETY: this binary has one test function, so no other thread reads the environment meanwhile.
    unsafe { std::env::set_var("PATH", path) };
    let read = leaks_during(|| {
        let key = load_key("op://v/item/password").unwrap();
        assert_eq!(*key, private);
    });
    assert_eq!(read, 0, "op read leaves a copy of the key");

    // A file whose text is one 16 MiB line: one block. Opening it may hold the text, one cleaned copy and the inflate
    // buffer; cleaning through a Vec<char> (4 bytes per character) or copying the block into the write buffer was
    // several times that (SPEC.md 5.4: the output budget is meant to bound memory).
    let line = "x".repeat(16 << 20);
    let file = file_of(&[&line]);
    assert!(file.len() < 1 << 20, "compresses well: a small input");
    let keys: KeyRing = key_ring();
    let inputs = [Input { name: "big.cipherlog".into(), bytes: file }];
    let mut written = 0usize;
    let peak = peak_during(|| {
        let mut sink = |s: &str| {
            written += s.len();
            Ok(())
        };
        write_report(&inputs, &keys, &[], &mut sink, &mut ReadBudget::default()).unwrap();
    });
    assert!(written > 16 << 20);
    assert!(peak < 72 << 20, "opening a 16 MiB line peaked at {} MiB", peak >> 20);
}
