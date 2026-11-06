# Host-side unit tests

Debug-only host tests for the pure logic of the KernelForge lab trio. They run
entirely on the dev host — no VM, no kernel, no provider services. The test
targets are compiled as Debug (`-O0 -DDEBUG` / `/Od /DDEBUG`); the runner
refuses any non-Debug build type.

## Run

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run-unit-tests.ps1
```

Four small executables are built into `out\tests\host\` and run in sequence:

| Executable | Toolchain | Why that toolchain |
|---|---|---|
| `kf_driver_tests.exe` | msys64 `clang64` | the driver unity's fragments use GNU-style inline asm (`intrin.hpp`) |
| `kf_postbox_crypto_tests.exe` | msys64 `clang64` | `PostboxCrypto.h` is freestanding C++ (no Win32) |
| `kf_postbox_client_tests.exe` | msys64 `clang64` | `User/pure.h` is freestanding C++ (parser + protocol lengths) |
| `kf_mapload_tests.exe` | MSVC (`cl.exe` via vcvars64) | mapload's CRT surface (`_strtoui64`, `sprintf_s`) and the mapload product itself are MSVC |

Exit code 0 with four `0 failed` summaries means green.

`scripts\run-f1-tests.ps1` builds `f1_job_tests.exe` into `out\tests\f1\` with
the same clang64 toolchain and runs it. It covers the job batch ABI and
validators and is not part of the four-suite unit runner.

## What is covered

### `driver_tests.cpp` — Engine-ci/Driver freestanding fragments

Replicates `main.cpp`'s unity order (`Lib/structs.h` → `Lib/utils.h` →
`Crypt.cpp` → `Scan.cpp`) and includes the fragments directly, so the tested
code is the product source, not a copy.

| Product | Tests pin |
|---|---|
| `Crypt.cpp` — `XorSeed`, `Encode`, `Decode`, `EncodeName`, `EncodeBytes` | XOR involution; exactly N−1 elements transformed; per-name encode contract for all 25 driver-encoded names (19 `PostboxResolve` imports + 2 `Mem` data exports + 4 NMI names): no NUL inside, every byte ≥ 0x80 (defeats plain-ASCII and ROT1 scans), exact `byte ^ SEED` decode symmetry, terminator preserved, name fits the 40-byte storage |
| `Scan.cpp` — `HexToByte` | digit/uppercase/lowercase mapping; invalid input returns `0xFF` (documented) |
| `Scan.cpp` — `PatternToBytes` | hex pairs, single `?` wildcard token, space handling, empty signature, mixed-case nibbles, the `"0?"` low-nibble quirk, `Pattern<N>` Encode/Decode round trip |
| `Scan.cpp` — `SignatureScan` | leftmost-match semantics, `?` sentinel coverage, all-wildcard first-position, first-byte reject path, no-match, range-shorter-than-signature guard, exact-size range, reversed range, null end/signature, empty signature |
| `Scan.cpp` — `FindFuncExports` / `FindFuncExportsBatch` | export-table walk on a mapped-layout mini PE: name -> RVA resolution for two names, missing name -> null slot, no export directory -> null, batch fill/order |
| `Scan.cpp` — `SectionScan`; `Locate.cpp` — `ScanModuleImage` | PAGE-first then .text fallback on a mapped-layout mini PE, missing section, null base |
| `Locate.cpp` — `ResolveRipRelative` | negative and positive disp32, instruction-size arithmetic |
| `Strings.h` — encoded names + pattern table | decoded names equal the plaintext (`ntoskrnl.exe`, `PAGE`, `.text`, `ci.dll`, `WdFilter.sys`); pinned pattern lengths (PiDDBCacheList 17, PiDDBCacheTable 15, MmUnloadedDrivers 10, MmLastUnloadedDriver 9, PteBase 13, PfnPteAddress 18); every pattern nonzero/≤64 and free of a literal `0x3F` (the wildcard sentinel) |
| `Lib/pure.h` — `WideEqualsIgnoreCase` | case-folded match (`Ci.dll` vs `ci.DLL`), B must end exactly at Count, A must not end early, empty strings |
| `Lib/pure.h` — `IsObjectKernelPointer` | `0xFFFF800000000000` floor accepted, `0xFFFF7FFF…`/user VA/0 rejected |
| `Scan.cpp` — string helpers | `StringLength`, `StringEquals` (case-sensitive + prefix cases), `BytesEqual` (null/0), `WideStringLength`, `WideStringEquals` (byte compare + prefix cases) |

**Documented quirks pinned by the tests:**
- `XorSeed` never transforms the *last* array element (trailing-NUL convention).
  `EncodeBytes(std::array<char,N>)` therefore loses a non-zero last byte.
  Runtime callers pass `Pattern<N>`, whose last byte is the terminator.
- `PatternToBytes("4A ?? 60")` is one `?` sentinel + a hex pair (len 3), not two
  wildcards: after a `?` the parser advances two characters and consumes the
  second `?`.
- `SignatureScan` takes the **decoded** signature bytes (`PatternToBytes`
  output), not the textual pattern string.
- A literal `0x3F` byte in a decoded signature is treated as a wildcard,
  because `'?'` (0x3F) is the wildcard sentinel. No current `Strings.h`
  signature contains 0x3F; the test pins the behavior for future pattern
  authors.

### `postbox_crypto_tests.cpp` — Common/PostboxCrypto.h

Correctness is pinned against **independent references**, not self-consistency:

| Product | Tests pin |
|---|---|
| SipHash-2-4 | reference-implementation vector (key 00..0f, empty message → `726fdb47dd0e0e31`); streaming Update/Final equals one-shot for every length 0..80 and every split point; key/message sensitivity |
| ChaCha20 | **RFC 8439 §2.3.2 block-function KAT** (key 00..1F, nonce `…09…4A…`, counter 1 → the full 64-byte expected block); sigma-mask products; `ChaCha20BlocksFor` boundaries incl. `kMaxBodyBytes == 255`; exact counter-wrap boundary (`0xFFFFFFF8+8` allowed, `0xFFFFFFF9+8` rejected without writing, last block fits, +2 blocks rejected); XOR involution at counters 0 and 7 |
| Key schedule | `DerivePostboxKeys` deterministic, all 32 master bytes wiped, distinct-master separation; layout proven by recomposition from the RFC-verified `ChaCha20Block` (32/16/16 split); `WipePostboxKeys` zeroes the block |
| Nonces | body/header nonce LE construction and the `kHeaderNonceXor` bit-31 relation |
| Seal/open | body round trip; header seal covers exactly `0x0C..0x1F` (bytes `0x00..0x0B` and `0x20..0x3F` unchanged); wrong-nonce open does not restore plaintext; header/body nonce domains differ; response wrappers round-trip; zero-length no-op; maximum body `0x3FC0` (255 blocks) round trip |
| MACs | `Mac128Equal` detects `0x01`/`0x80`/`0xFF` flips in every position; `Mac128Final` wipes the state; **independent canonical-byte encodings** for request and response (field order, LE widths, header/body coverage) equal the one-shot tags; tampered body/header/session/seq/nonce/status/ack rejected; body coverage only for `pb_write` (request) and `pb_read`/`pb_nmi` (response); request/response domain separation |
| Header accessors | LE round trips for Seq/Ack/Status/Op/Pid/Size/Address/Nonce/Session/Mac; negative status; const `HeaderMac` overload |
| `PostboxConfigValid` (shared `Common/Postbox.h`) | valid config accepted; every invalid field rejected with the `PostboxStartFailure` entry code (30): magic, version, pid, mailbox VA (zero/unaligned/past the user limit), create time, session, ntoskrnl base, `Reserved` independent-page bit, all-zero key, each of the three independent-page helpers; `Reserved=3` accepted (only bit 0 matters); purity (no config mutation) — the driver now validates before `MemSetPreStartNtoskrnl` |
| Page flags + body lengths (shared `Common/Postbox.h`) | `PostboxMergePageFlags` precedence Rx > RwNx > RNx (later read-only does not downgrade a writable page); `PostboxRequestBodyLen` (pb_write only); `PostboxResponseBodyLen` (failure → 0, pb_read → Size, pb_nmi → 8, ping/write/stop → 0) |
| Poll decision helpers (shared `Common/Postbox.h`) | `PostboxSequenceVerdict`: next Seq / same-Seq idle (session+nonce+Ack) / same-Seq stop candidate / replay+wrong-session auth failure / `0xFFFFFFFF -> 0` wrap; `PostboxRequestShapeOk`: known op, zero-body ops must be Size 0, other ops nonzero, same-Seq only for pb_stop; `PostboxRequestRangeOk`: null/past-user-limit/stage-bound rejects, strict `Address+Size < PostboxUserLimit`, write-over-header reject (read allowed), exact mailbox-start edge |
| ABI/protocol | `PostboxKeys` 64 B, `PostboxHeader` 0x48, `PostboxSectionHandoff` 0x48, `PostboxConfig` 0x110, `PostboxImageLayout` 0xB0, magic IDs, all field offsets, op/page-flag/handshake-state values, `PostboxBytes/DataAt/DataMax`, `PostboxSectionBytes/Version`, `kHeader*`, `kMaxBodyBlocks` |

### `mapload_tests.cpp` — mapload mapper + controller fragments

`mapper/map.cpp` and `controller/config.cpp` are included as fragments (their
logic is `static`/anonymous) with the control layer and the KernelForge
foreign-memory API stubbed. The `Log()` stub forwards to stdout with a
`[stub-Log]` tag, so the product's own reject-branch messages appear in the
test output.

| Product | Tests pin |
|---|---|
| `mapper/map.cpp` — `RangeInImage` | in-range/out-of-range/overflow guard; the documented `offset == imageSize && length == 0` in-bounds edge |
| `mapper/map.cpp` — `ApplyRelocs` | DIR64 patching by delta, ABSOLUTE skip, HIGHLOW (type 3) applies the low-32 delta and rejects an out-of-image target, `RelocProbe` first-patch capture (and non-overwrite when pre-filled), empty-directory no-op, reject paths: size-without-RVA, directory range outside image, malformed block size, zero block, DIR64 target outside image, unsupported relocation type |
| `mapper/map.cpp` — `ResolveImports` | ntoskrnl-only by-name resolution end to end with **exact IAT address and resolved-name assertions**, ILT unchanged, terminator zero; rejects: directory smaller than a descriptor, module-name RVA outside the image, ordinal import, by-name RVA outside, `FirstThunk == 0`, descriptor table outside, 256 descriptors without a terminator, empty/non-ntoskrnl module; `NTOSKRNL.EXE` accepted (case-insensitive); `{0, nonzero}` resolves trivially (documented asymmetry with `ApplyRelocs`) |
| `mapper/map.cpp` — `StripImportMetadata` | import directory cleared, descriptor zeroed, module-name string wiped, **IAT survives**, ILT and hint/name entry zeroed; `OriginalFirstThunk == 0` leaves the hint/name string resident (documented limitation — the product only walks the OFT) |
| `mapper/map.cpp` — `MapImage` (end to end) | full publish path against a fake kernel heap (kernel-range addresses translating to host buffers): PE validation rejects, section copy, page-aligned and unaligned base modes, independent-pages allocation, relocation patch + provider readback verification, IAT patch, headerless publish, `.reloc`/`.pdata` zeroing (and `.pdata` preservation when `StripPdata=false`), ROT1 table head RVA/size (11 slots = 440 bytes, the needle is in slot 10) |
| `controller/config.cpp` — `Parser`/`LoadConfig` | full JSON object, defaults, unknown keys skipped, bool/negative/fraction rejects, providers list/empty list, string escapes (`\u0042`, `\n`, `\/`, `\\`, non-ASCII → `?`, unknown escape), malformed inputs, documented quirks (trailing text after `}` accepted, leading-zero octal), `LoadConfig` success with `cfg.path`, BOM, empty/truncated files, missing file |
| `controller/pure.h` — bootstrap helpers | `IsAbsolutePath`/`JoinPath` (incl. documented Windows-semantics quirks), `ParseU64Arg` (hex/decimal/garbage/overflow quirk), `PostboxSectionHandoffValid` (every field, alignment and user-limit edges), `PostboxHashBytes`/`PostboxMarkerPresent` (pinned custom-FNV values, reason strings), `ResolveDriverPath` precedence (CLI > postbox default > config > release > debug > canonical), `FillPostboxImageLayout` (header + section map, Rx/RwNx/RNx flags, PE32+/size rejects), `FindWorkspaceRootFromExe` (out\build walk, fallback, skip-without-build) |
| `controller/pure.h` — loader teardown | `FindRot1Table` anchors at the table head (needle in slot 10 → RVA 0x2A00/440, not 2 slots/80); `PostboxPageProtection` Rx→`PAGE_EXECUTE_READ`, RwNx→`PAGE_READWRITE`, RNx→`PAGE_READONLY`; `ZeroSectionByName` zeroes `.reloc`/`.pdata`, VirtualSize 0 → RawSize, absent/out-of-range → no-op, crossing the end clamps; `FreeMappedImageZeroed` (independent → physical write then free, pool → KfMemSet then free, base 0 no-op, size 0 free-only, wipe failure still frees + logs); `CreatePostboxConfigPage`/`FreePostboxConfigPage` (alloc/copy/protect/free on every failure path, wipe then free) |
| `config.cpp` — default search order | `LoadConfig("")` workspace `mapload.json` wins, malformed workspace file is a hard failure (no exe-dir fallback), no file → defaults, exe-dir fallback when the workspace has none |

### `postbox_client_tests.cpp` — Engine-ci/User/pure.h

| Product | Tests pin |
|---|---|
| `ParseMilliseconds` | `0`/`1000`/`4294967295` accepted; overflow, sign, trailing garbage, empty, leading space, null rejected |
| `ParseArguments` | `--kill`, `--hold`/`--hold-ping` values, `--loader`/`--loader-args`, unknown arguments ignored, missing values are hard errors; NMI/STACK probe flags when compiled with those defines |
| `PlanStopBestEffort` | Seq 0 → no stop; nonzero → submit pb_stop with the same Seq (same-Seq stop / LastSeq+1 semantics) |
| `PostboxResponseBodyLen` / `PostboxRequestBodyLen` | failure → 0, pb_read → Size, pb_nmi → 8, probes → fixed structs (NMI_PROBE/STACK_PROBE build), pb_write request → Size only |

### `f1_job_tests.cpp` — job batch ABI and validators

| Product | Tests pin |
|---|---|
| `PostboxJobConfig` / `PostboxJobBatch` | struct sizes and field offsets, section-header layout, magic/version values, `PostboxJobMax`/`PostboxJobMaxBytes`/`PostboxJobSectionMax` |
| `PostboxJobConfigValid` / `PostboxJobBatchValid` | every reject branch (magic/version/reserved, pid/create-time pair, section VA/size bounds, count, layout, import slots, job op/size/range/data offset) and the exact accept edges, including the full 32-byte key check; validation is pure |
| `PostboxJobCrypto.h` | SipHash key/body sensitivity; `JobCryptBatch`/`JobCryptData` round trips, request/result domain separation, chunked-keystream continuity; end-to-end seal/authenticate/open/validate flow |

### Kernel DEBUG self-tests (`#ifdef DEBUG` in `Engine-ci/Driver`)

The kernel-only paths cannot run on the host, so they are covered by DEBUG-only
self-tests following the existing `VerifyPteBase`/`VerifyMemory` pattern. Release
builds compile both the calls and the functions out.

| Self-test | Call site | What it pins |
|---|---|---|
| `VerifyMemSetPreStartNtoskrnl` (`Mem.cpp`) | DriverEntry step 0.7 | `CachedPsInitialSystemProcess` / `CachedPsLoadedModuleList` equal the `__imp_*` data-export addresses; the SEED-XOR `MemDecodeName` recovers `PsLoadedModuleList`; decoded buffers are wiped |
| `VerifyProcessEnumeration` (`Process.cpp`) | DriverEntry step 0.8 | `EnumerateEProcess(L"System", 4) == PsInitialSystemProcess`; `EnumerateKProcess(L"ntoskrnl.exe") == GetNtoskrnl()`; a missing process returns null; the System PEB walk returns null |
| `VerifyFindFuncExports` (`Scan.cpp`) | DriverEntry step 0.9 | the real ntoskrnl export walk returns the same addresses as the `__imp_PsInitialSystemProcess`/`__imp_PsLoadedModuleList` slots; a missing name returns null; the batch fills the same results |
| `VerifyPostboxStateWipe` (`Postbox.cpp`) | DriverEntry step 6.5, after `PostboxStart` | the consumed `Cfg` copy is all zero; derived keys are non-zero; `SessionId`/`MailboxVa`/`Stage`/`Process` are set; the import table was adopted; `PostboxWipe` zeroes every byte and tolerates null |
| `VerifyPostboxResolveNames` (`Postbox.cpp`) | step 6.5 | every adopted import (`PostboxResolve`'s names plus the independent-page helpers) is non-null — every encoded name decoded and resolved |
| `VerifyPostboxStage` (`Postbox.cpp`) | step 6.5 | the NX stage exists, is an independent-page allocation, the reaper range is non-empty, and the stage-size constants match the protocol |
| `VerifyModuleListRoundTrip` (`Hide.cpp`) | DriverEntry step 2.5 (SCM profile) | the loader entry is in `PsLoadedModuleList`, `UnlinkDriverFromModuleList` removes it, `RelinkDriverIntoModuleList` restores it |
| `VerifyPeHeaderRoundTrip` (`Hide.cpp`) | step 2.6 | `ErasePeHeader` removes MZ/PE, `VerifyPeHeaderRemoved` confirms, `RestorePeHeader` restores MZ and the NT signature |
| `VerifyEmptyTraceState` (`Traces.cpp`) | step 2.7 (SCM profile) | a second clear pass over the already-empty PiDDB / MmUnloadedDrivers / CI hash-bucket / WdFilter state succeeds and the verifiers find no record naming this driver |
| `VerifyPostboxRequestAuth` (`Postbox.cpp`) | step 6.5 | live keys/session: a sealed request's tag is stable and accepted; tampered body/header and wrong session/seq/nonce are rejected; the sealed header/body open back to the wire values; `pb_read` does not cover the body; the poll's sequence arithmetic accepts only `Ahead == 1`, including the `0xFFFFFFFF -> 0` wrap |
| `VerifyPostboxRespondTag` (`Postbox.cpp`) | step 6.5 | `PostboxRespond`'s tag composition verifies client-side from the published header; `Ack == Seq`; status, ack and body are covered; request/response domains do not collide |

`VerifyPostboxSelfTest` runs the five Postbox checks and logs one verdict. The
`PostboxPollAttached` decision rules are shared helpers in `Common/Postbox.h`
(`PostboxSequenceVerdict`, `PostboxRequestShapeOk`, `PostboxRequestRangeOk`) and
are host-tested in `postbox_crypto_tests.cpp` (same-Seq stop, idle keepalive,
replay/nonce, op/size rules, header-overlap write, user-limit bound).

The DEBUG variant is built with `-DDEBUG_BUILD=ON -DPOSTBOX_NMI=OFF`
(Ninja + clang64, `CMAKE_BUILD_TYPE=Debug`); the release build is unchanged.

#### Live DEBUG run (lab VM, KDNET)

The DEBUG driver was mapped on the lab clone (`net:port=50001,key=1.2.3.4`) with
a loader built for the DEBUG driver's FNV. DbgPrint output confirmed:

```
[*]DriverEntry: step 0.7 VerifyMemSetPreStartNtoskrnl()
[*]DriverEntry: step 0.8 VerifyProcessEnumeration()
[*]DriverEntry: step 0.9 VerifyFindFuncExports()
[*]DriverEntry: step 6 PostboxStart()
[*]DriverEntry: step 6.5 VerifyPostboxSelfTest()
[*]Postbox: DEBUG self-tests passed
[*]DriverEntry: success
```

The client's full protocol then passed (ping, read, write, negative read/write,
bulk write/read, 3 s hold). After the hold the driver stopped, the self-free
reaper armed, and the target stayed alive — no fault. `PostboxFreeState` /
`PostboxReaperPrepare` free the stack-spoof shadow only after the spoofed worker
quiesces.

The SCM-only self-tests (`VerifyModuleListRoundTrip`, `VerifyPeHeaderRoundTrip`,
`VerifyEmptyTraceState`) are retained for a non-`MANUAL_MAP_ONLY` build; the
shipped Postbox profile excludes `Hide.cpp`/`Traces.cpp`, so they do not run
there.

SCM execution is blocked by the clone, not by the tests. Test signing was enabled
(`bcdedit` shows `testsigning Yes`), the `WDKTestCert` was imported into
`Root` + `TrustedPublisher`, and `Get-AuthenticodeSignature` reports
`Status: Valid / Signature verified`. `sc create` succeeds, but `sc start`
returns **487 (ERROR_INVALID_ADDRESS)** with no `DriverEntry` DbgPrint and no
CodeIntegrity block event. The **known-good release SCM driver**
(`build-nohook-release\Driver.sys`) fails identically on the same clone, so the
guest itself cannot load SCM kernel drivers (it is a manual-map lab image).
Those three self-tests are compile-verified; the Postbox-profile self-tests above
were executed on the clone.

## Product bugs / findings surfaced by the tests and the review

| Finding | Status |
|---|---|
| `mapload/controller/config.cpp`: `Parser` stored its input as `const std::string&`, so `Parser p("literal")` dangled | **Fixed** (stores `std::string` by value) |
| `Postbox.cpp`: `MemSetPreStartNtoskrnl` ran before config validation, so an invalid config resolved kernel exports before rejection | **Fixed** — validation now runs first via shared `PostboxConfigValid` (`Common/Postbox.h`) |
| `mapload/mapper/map.cpp`: ROT1 table scan needle `"LfJojujbmj"` matches the ROT1 of the `KeInitialize` prefix in the 10th slot, so the old scan reported the *needle* offset and wiped only 2 of 11 entries (80 of 440 bytes) | **Fixed** — `FindRot1Table` (now `controller/pure.h`) walks back over contiguous 40-byte slots to the table head, then counts forward; the MapImage fixture is an 11-slot table and asserts `0x2A00/440`. Note the current driver no longer carries a ROT1 table (NMI names are SEED-XOR `EncodeName`), so this is a legacy-artifact path |
| `StripImportMetadata` with `OriginalFirstThunk == 0` leaves the hint/name entry resident (only the OFT is walked; `ResolveImports` already overwrote the FirstThunk by-name RVAs) | Documented + pinned by test; the normal PE shape has a separate OFT |
| `ApplyRelocs` accepts `{VirtualAddress=0, Size=0}` but rejects `{0, nonzero}`; `ResolveImports` accepts `{0, nonzero}` as "none declared" | Documented asymmetry, pinned by tests |
| Postbox watchdog/self-free reaper after a client timeout: the DEBUG run passed every self-test, then the target faulted at `RIP=0` (`ACCESS_VIOLATION_NULL_IP`, process `System`, `Win32 Start Address nt!ExpWorkerThread`) right after `Postbox: reaper armed` | **Fixed** — `PostboxFreeState` called `PostboxFreeShadow()` from inside `PostboxPollSpoof`, so the active worker's spoof epilogue returned through a freed/zeroed trampoline. The shadow is now freed only in `PostboxReaperPrepare` after `PostboxInFlight` quiesces; the timer/DPC wipe also moved to the reaper's post-grace full-page wipe. Verified by rerunning the client timeout/stop: reaper armed, target still running 5 s later, no RIP=0 |
| `Postbox.h`: default `POSTBOX_BUILD_HASH` is stale versus the current `Driver.sys`; a plain build without `scripts/build-postbox.ps1` refuses the driver | Reported; the build script passes `-D`, so the shipped path is correct |
| `mapload/main.cpp` `IsAbsolutePath`: `C:foo` returns true (drive-relative) and `\foo` false (single-rooted paths are absolute on Windows) | Reported, not fixed (pinned by test as documented semantics) |
| `PostboxUserLimit` / config version / `Reserved` bit were duplicated literals across driver and loader | **Fixed** — `PostboxUserLimit`, `PostboxConfigVersion`, `PostboxConfigReservedIndependent` live in `Common/Postbox.h` and both sides use them |
| `SignatureScan` treats a literal `0x3F` as a `?` wildcard sentinel | Documented + pinned by test; no current signature is affected |

## Deferred coverage (explicit next steps)

| Area | Why deferred | Suggested approach |
|---|---|---|
| `PostboxPollAttached` full decision path with a real client mailbox | the poll reads/writes the client's user VA through `MmCopyVirtualMemory`; a start-time self-test must not consume the live sequence/nonce or touch the live mailbox | lab VM with `PostboxClient.exe` (ping/read/write/stop, replay and tamper negatives) over KDNET; the crypto/sequence core is covered by `VerifyPostboxRequestAuth` |
| `Postbox` timer/DPC/watchdog/reaper lifecycle | the live DEBUG run found a `RIP=0` fault after the client-timeout watchdog armed the self-free reaper (image freed while a DPC/timer path still executes); the self-tests themselves passed | lab VM + KDNET: reproduce with a client that never pings, break on `nt!KeBugCheckEx`, inspect the reaper/DPC ordering and `PostboxInFlight`/DPC-ref quiesce |
| `PostboxNmi` gate, `Hide.cpp`/`Traces.cpp` detection | constructed IDT, real anti-cheat lists | lab VM + KDNET breakpoint kit (`mapload/scripts/kd_breakpoints.txt`) and `check_detection_vectors.ps1` |

## Adding a test

- Driver-side pure code: extend `driver_tests.cpp`; keep the unity include order.
- Client parser/protocol code: extend `postbox_client_tests.cpp`.
- Job batch ABI/validators: extend `f1_job_tests.cpp` (run via
  `scripts/run-f1-tests.ps1`).
- Mapload-side pure code: extend `mapload_tests.cpp`; stub new externs in the
  stub block (control layer + KernelForge symbols) and keep `Log()` forwarded.
- Use the `CHECK(...)` micro-harness; one behaviour per check; when pinning a
  quirk, state the product source line in the comment.
- Re-run the script; a red test must name the product function and the input.
