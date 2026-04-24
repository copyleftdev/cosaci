//! `cosaci-demo` binaries.
//!
//! Stub. The working `demo` and `demo_networked` binaries still live
//! at `src/bin/{demo,demo_networked}.rs` (root cosaci package) until
//! issue #4 moves them here. After the move this crate will expose
//! both as binaries via `[[bin]]` entries.

fn main() {
    eprintln!(
        "cosaci-demo: not yet moved out of src/bin/. \
         Use `cargo run --bin demo` or `cargo run --bin demo_networked` \
         for the working v0.1 binaries; see issue #4 for the move PR."
    );
}
