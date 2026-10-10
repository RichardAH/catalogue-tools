# catl — Xahau catalogue toolkit

A self-contained C++20 toolkit for the catalogue files produced by xahaud's
`catalogue_create` RPC: **explore**, **verify**, **merge**, **split**,
**look up** objects and transactions, **anchor** a whole set against the live
network, and **fetch** the canonical set from <https://cat.xahau.network/>.
It has a scriptable CLI and an XTree-Gold-style interactive browser.

```
make && ./catl fetch -d /data/cat --latest 2 -y && ./catl verify /data/cat --remote && ./catl tui /data/cat
```

## Dependencies

None for the core. SHA-512/256/1, base58check, the zlib/deflate codec (both
directions), SHAMap, the XRPL binary codec, JSON, HTTP/1.1 and the WebSocket
client are all inlined. OpenSSL (`libssl-dev`) is used **only** for `wss://` and
`https://`; it is auto-detected, `make TLS=0` builds without it (then plain
`ws://` / `http://` endpoints still work, e.g. a local node). TLS verifies the
certificate chain and hostname against the system store (`SSL_CERT_FILE` /
`SSL_CERT_DIR` override it, e.g. for a private node).

```
make            # ./catl
make test       # ./catl_tests: 131 checks, incl. real-chain vectors
make install    # PREFIX=/usr/local
# or: cmake -B b && cmake --build b
```

## Getting the canonical set

The canonical catalogues are large (≈1.7 TB for ledgers 1–21,000,000 as of
October 2026, 11–288 GiB per file), so pick what you need:

```
catl fetch -d /data/cat                     # list: exact sizes, upstream status, what you have, free space
catl fetch -d /data/cat --latest 2 -y       # newest two finished files
catl fetch -d /data/cat --from 14000000 --to 15000000 -y
catl fetch -d /data/cat 16500001 -y         # the file containing that ledger
catl fetch -d /data/cat --all -y            # everything
catl fetch -d /data/cat --print-commands    # resumable curl commands instead
```

`fetch` reads each remote file's 88-byte header with a Range request, so it
knows exact sizes and whether upstream is **still writing** a file
(`catalogue_create` fills in filesize and hash only at the end; such files are
skipped unless `--include-unfinished`). Downloads resume from `.part` files,
the file SHA-512 is computed while streaming (a resumed download re-hashes the
existing part first) and must match the header before the file is renamed
into place; a mismatch keeps the `.part` and fails loudly. `scripts/fetch-canonical.sh` is a curl-only
fallback. In the TUI press **F**.

## Commands

| command | what it does |
|---|---|
| `info FILES` | header, range, compression, network, size consistency, index status |
| `verify FILES\|DIRS [--quick] [--no-hash] [-j N] [--remote [URL]] [--server URL]…` | full verification (below); `-j` verifies files in parallel |
| `anchor FILES\|DIRS [--server URL]…` | network anchoring using the indexed (stored) header hashes |
| `ls FILE [--from N --to M --limit K]` | ledgers with close time, tx count, state-delta size |
| `ledger FILES SEQ [--json] [--state]` | header (hash recomputed), transactions, state changes |
| `get FILES [--ledger N] KEYLET… [--history] [--hex]` | object as of any ledger; `--history` lists every version |
| `tx FILES TXID [--ledger N]` | decoded tx + metadata (without `--ledger` it scans) |
| `merge -o OUT FILES [--level 0-9]` | contiguous or overlapping files → one file |
| `split FILES -o DIR --every N \| --at A,B \| --range A-B` | repartition (aligned like the canonical names by default) |
| `extract FILES --range A-B -o OUT` | one sub-range |
| `index FILES [--rebuild]` | build the sidecar index |
| `keylet SPEC…`, `decode HEX… [--tx]` | key computation, binary → JSON |
| `tui [DIR\|FILES]` (or `catl -i`) | interactive browser |

Keylet specs: `account:r…`, `owner_dir:r…`, `page:ROOT:N`, `signers:r…`,
`line:rA:rB:USD`, `offer|escrow|check|ticket|nft_offer:r…:SEQ`,
`paychan:rA:rB:SEQ`, `deposit_preauth:rA:rB`, `hook:r…`, `hook_def:HASH`,
`hook_state:r…:KEY:NS`, `hook_state_dir:r…:NS`, `emitted:TXID`, `emitted_dir`,
`uritoken:r…:URI` (or `hex:…`), `import_vlseq:PUBKEY`, `did:r…`,
`skip[:SEQ]`, `amendments`, `fees`, `nunl`, `unl_report`, or raw 64-hex.

All set-level commands accept any mix of files and directories, sort by range
and pick the right file for a ledger.

## What `verify` checks

Per file, in one sequential pass:

* header: magic, version, `filesize` vs the real size (truncated/partial
  downloads), unfinished files flagged rather than failed;
* the whole-file **SHA-512** (header hash field zeroed, exactly as xahaud);
* every ledger in sequence; state section applied to an in-memory **SHAMap**
  (removal of absent keys, duplicates, wrong node types are errors);
* recomputed **account_hash**, **transaction_hash**, **ledger hash**
  (`SHA512Half('LWR\0'‖header)`) against the stored ones;
* every tx key is `SHA512Half('TXN\0'‖tx)` and every leaf is `VL(tx)‖VL(meta)`;
* `parent_hash` links (and `parent_close_time`) within the file; trailing data.

Across files: sorted by range, gaps and network mismatches are errors,
`first.parent_hash == previous.last.hash` at every boundary, overlaps are
checked through common flag-ledger hashes. Since the chain is fully linked,
confirming **one** hash anywhere in it anchors all of it.

Memory is about the size of the state map (the SHAMap is canonical and
incrementally hashed — only paths touched by a ledger are rehashed). Verify
also writes the sidecar index as a by-product.

## Anchoring to the live chain (`--remote`, `anchor`, TUI **A**)

Against `wss://xahau.network` (or any `--server`, repeatable; results must
agree):

1. fetch the **validated** ledger header in binary and recompute its hash;
2. for every flag ledger (seq % 256 == 0) in the set, read the long
   **LedgerHashes** object (`keylet::skip(seq)` = `SHA512Half('s'‖seq>>16)`)
   from the validated state and compare — one request per 65,536 ledgers, and
   it only needs *current* state, so any server works, not just full-history;
3. for the end of the range: if it is within `--walk-limit` (2000) of the tip,
   a **trustless parent-hash walk** from the validated header (every header
   rehashed locally); else within 256 via the short LedgerHashes list; else
   the next flag ledger's hash plus a walk down (needs a history server).

Trust model: step 3's walk trusts only the validated tip; skip-list reads trust
the server's state (there is no state-proof RPC), which is why multiple
`--server`s are supported. Mismatches are reported per ledger.

## Merge / split

One repack engine streams the inputs once, keeps the state map, and writes
any set of output ranges: each output starts with a full state dump, later
ledgers are leaf deltas exactly like `catalogue_create`. When a later input's
first ledger is a full dump it is converted into a delta against the running
state (merge-join), overlaps are skipped after checking the hashes agree,
and with verification on (default) nothing is written unless every ledger's
hashes check out. Splitting a file and merging the parts back reproduces the
original byte-for-byte (tested). Output compression defaults to the first
input's level; `--level` changes it (level 0 = uncompressed, as xahaud).

## Sidecar index and random access

`$CATL_INDEX_DIR`, else `$XDG_CACHE_HOME/catl`, else `~/.cache/catl` (a
`<file>.catlidx` beside the file is also honoured). Per ledger: stream offset,
item counts, close time; plus stored flag-ledger hashes and, for compressed
files, inflate checkpoints (32 KiB window + bit offset, every 64 MiB of
output, windows themselves deflated) so any ledger in a multi-hundred-GiB
zlib stream is reachable without decompressing from the start. Indexes are
keyed by filesize + header hash and rebuilt when a file changes.

Note on lookups: state is cumulative, so `get` replays the file containing
the ledger from its base (full dump) — fast near the start of a file, a
sequential read of the file otherwise. Smaller files (`split`) make it faster.

## Interactive mode

```
 Path: Catalogue tree › cat.14000001-14100000 › Ledger 14050121        CATL-TREE  08:09:13
┌─ Ledger 14050121 ──────────────────────────────────┬─ Info ─────────────────────┐
│ Transactions (5)                                   │ LEDGER     14050121        │
│  63E714ACB66963F8…  Payment       r9kVY…  tesSUCCESS│ Hash       2FAA415F81CB…   │
│ State changes — 8 items                            │ Recomputed ✓ matches       │
└────────────────────────────────────────────────────┴────────────────────────────┘
 CATL  Verify  Anchor  Index  Lookup  Tx  Goto  Merge  Split  Fetch  Rescan
 COMMANDS  ◄─┘ ledgers   Space tag   F1 help   ^C cancel job   Q quit
```

Tree of files (gaps and overlaps shown inline, verification status per file)
→ ledger list → ledger (transactions and state changes) → decoded object
(X toggles raw hex, H shows a key's history). Long jobs (verify, index,
merge/split, downloads, anchoring) run in the background with progress in the
info pane; ^C cancels. Plain ANSI/termios, no curses.

## Format notes (from xahaud `Catalogue.cpp` / `CatalogueStream.cpp`)

```
File    := CATLHeader(88) Body            all integers host/little endian, packed
Header  := magic "CATL" u32 min u32 max u16 version(bits 0-7 version, 8-11 zlib level)
           u16 network_id u64 filesize u8[64] sha512(file with this field zeroed)
Body    := Stream | zlib(Stream)          one zlib stream, window bits 15
Ledger  := seq u32, hash, tx_hash, account_hash, parent_hash (32 each), drops u64,
           close_flags i32, close_resolution u32, close_time u64, parent_close_time u64
           StateSection TxSection         (164-byte header)
Section := (type u8, key 32, size u32, data | 0xFE key) … 0xFF
```

Two latent issues in the writer, harmless today but worth fixing:

* `serializeSHAMapToStream` with a base map returns **without writing the
  0xFF terminator** when the state hash is unchanged; the loader would then
  read the tx section as a state delta. It never triggers on a live chain
  only because LedgerHashes changes every ledger. catl always terminates.
* if `SHAMap::compare` returns false the writer falls back to a **full dump
  with no removals**, which the loader applies as upserts — stale keys, hash
  mismatch, unusable file (catl's verifier reports it).

## Testing

`make test` runs real-chain vectors (an XPOP fixture from xahaud: ledger hash,
txid, tx-leaf and tx-root), xahaud's SHAMap build/tear vectors, well-known
keylets and amendment IDs, the codec against truncation/corruption, and
end-to-end synthetic catalogues (raw and zlib): verify, index + checkpoint
seeks, lookups against ground truth, split/merge/overlap/extract, gap
detection, corruption and truncation. For remote anchoring without the
network: `./catl_tests --make-sample /tmp/s/cat` writes a sample set plus
`chain.json`; `tools/fake_xahaud.py /tmp/s/cat/chain.json 8765 [--tamper]`
serves it, then `catl verify /tmp/s/cat --remote ws://127.0.0.1:8765`.

Protocol tables (fields, tx/ledger-entry types, TER codes, amendment names)
are generated from xahaud's own macro files:
`tools/gen_protocol_defs.py /path/to/xahaud > src/protocol_defs.inc`.
