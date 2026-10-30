# Command channel: design choice and implementation

**Status:** implemented as an opt-in build (`POSTBOX_CHANNEL`); the default build and its
shared-memory channel are unchanged. The final build (KDPC 0x40, per-poll attach, full-range/self-only
address policy, ordered response) compiles, signs, and has passed a live ping/read/write/stop plus a
`0x8000`-byte bulk round trip on the 19041 clone with KDNET `50001`; evidence is in
`out/vm-test/postbox-l6-20261029/` (the NMI build adds the transient constructed-IDT gate and
`pb_nmi`). The `pre-driver-tests` snapshot still cannot restore (missing
`.vmem`), so the lab-VM E3/E4 sampling runs remain pending (see §8).

This is the engineering document for the channel. The detection analysis, the alternatives, and the
sensor-by-sensor evidence are in `out/research/AC-25_channel.md`; this file records what was chosen,
why, and how the code works.

## 1. Decision

**Chosen:** a client-owned mailbox in ordinary private memory, polled by a coalescable kernel timer,
drained by a deferred work item at `PASSIVE_LEVEL`, with all channel state static in the driver image.

**Not chosen:** the existing named section plus `PsCreateSystemThread` poller in `Channel.cpp`.

The existing channel works, but it is the most visible option on every axis:

| Artifact | Sensor that catches it |
|---|---|
| Named section `\Sessions\1\BaseNamedObjects\EngineCiShared` | object-directory enumeration |
| 1 MiB `SEC_COMMIT` view in the client | VAD enumeration |
| 1 kHz `PsCreateSystemThread` worker | thread enumeration and stack resolution (EMAC checks every frame against a signed module) |
| Plaintext `ECI1` header and commands | memory pattern scan |

Renaming the object or changing the magic removes none of those. The replacement moves each part to
the least-audited option:

| Part | Old | New |
|---|---|---|
| Shared location | named section + VAD | client's own private page (normal VAD/PTE, no object) |
| Trigger | dedicated system thread | timer DPC -> `ExQueueWorkItem` |
| Execution context | payload thread stack | existing system worker at `PASSIVE`, transient |
| Content | plaintext header/body (`ECI1`) | ChaCha20 header/body + 128-bit SipHash-2-4 tag; client CSPRNG key + PBK1 handoff |

**Consequences:** no named object, no handle, no section, no dedicated thread, no callback-list entry,
no hook. Residual artifacts are one armed `KTIMER` in the per-PRCB timer table, a transient worker-stack
frame during the poll, and the payload image itself (AC-12/AC-13, unchanged and still the main bound).

## 2. Architecture

```
client process (mailbox owner)              kernel
+-------------------------------+            +-----------------------------------+
| private page / heap arena     |  CR3       | PostboxWorkRoutine (PASSIVE)      |
| PostboxHeader + body          |<-----------|   PsLookupProcessByProcessId      |
| Seq/Ack/Op/Pid/Size/Address   |            |   AccessVirtualMemory / CopyVM    |
+-------------------------------+            |   execute, write Status + Ack     |
        ^                                    +-----------------------------------+
        | client polls Ack (frame loop or Sleep)             ^
        |                                       ExQueueWorkItem (DelayedWorkQueue)
        |                                                    ^
        |                                       PostboxDpcRoutine (DISPATCH)
        |                                                    ^
        |                                       KTIMER 4 ms requested / 250 ms idle
```

### 2.1 Data location

The mailbox is a 64 KiB private committed region owned by the client. The client can allocate it with
`VirtualAlloc` or inside its existing heap. The driver reads and writes it through the target `CR3`
with the existing manual page-table walk (`AccessVirtualMemory`, `CopyVirtualMemory` in `Mem.cpp`),
so there is no `MmCopyVirtualMemory` call. The mapped profile compiles out the dedicated map table
(`NO_MAP_TABLE`); the walk's map step claims a free PTE in the **current** process, and a system worker
has no suitable user page table. The work item therefore attaches to the mailbox process
(`KeStackAttachProcess`) for the duration of the poll, which gives the walk the client's user page
tables. It is a transient context switch per poll, not a persistent thread; the worker detaches before
the process reference is dropped. The page's VAD and PTE both describe a normal private page; there is
no section or prototype PTE, and no persistent kernel mapping; each poll claims a transient kernel PTE
in the client's page tables and releases it with `invlpg` before returning.

The protocol assumes the client keeps the page resident by polling `Ack`; a missing page is a failed
poll, not a fault. The driver never tries to fault it in.

### 2.2 Trigger

`KeInitializeTimerEx` + `KeInitializeDpc` + `KeSetCoalescableTimer` arm a periodic timer. The DPC runs
on the per-CPU DPC stack and does only two things: check `PostboxRunning`, and claim the in-flight
flag before calling `ExQueueWorkItem(&PostboxWorkItem, DelayedWorkQueue)`. It never touches user
memory, so it is safe at `DISPATCH_LEVEL`.

The work item runs in an existing system worker at `PASSIVE_LEVEL`. This is the only execution context
that can safely walk page tables, take the process reference, and copy memory. The worker is a
legitimate system thread; there is no thread whose start address or blocked stack belongs to the
payload.

### 2.3 State

All of it is static in the driver image (`.data` in the mapped nonpaged image), so the channel adds no
pool allocation:

```cpp
static PostboxTimer PostboxTimerObject;   // KTIMER, 0x40
static PostboxDpc   PostboxDpcObject;     // KDPC,   0x40 (ProcessorHistory at +0x10)
static PostboxWork  PostboxWorkItem;      // WORK_QUEUE_ITEM, 0x20
static volatile long PostboxRunning;      // 0/1
static volatile long PostboxInFlight;     // one work item at a time
static uint32_t      PostboxLastSeq;
static uint32_t      PostboxPeriodMs;     // 4 or 250
static uint32_t      PostboxIdleTicks;
static PostboxConfig PostboxCfg;
```

`Postbox.cpp` defines the three kernel layouts locally with `static_assert`s on the x64 sizes, rather
than depending on the vendor headers.

## 3. Wire protocol

One request is outstanding at a time. The client writes the request, then increments `Seq`; the driver
sets `Ack = Seq` after writing `Status` and any result. The client writes a normal request only while
`Ack == Seq`; after a timeout it may send a `pb_stop` with the last `Seq` and a new nonce.

### 3.1 Header (`Common/Postbox.h`)

| Offset | Size | Field | Meaning |
|---|---|---|---|
| `0x00` | 4 | `Seq` | client increments after a request is written |
| `0x04` | 4 | `Ack` | driver sets to `Seq` when done |
| `0x08` | 4 | `Status` | NTSTATUS of the last request |
| `0x0C` | 4 | `Op` | `pb_ping`, `pb_read`, `pb_write`, `pb_stop`; ChaCha20-encrypted |
| `0x10` | 4 | `Pid` | client-side diagnostic only; the driver uses `PostboxCfg.Pid`; encrypted |
| `0x14` | 4 | `Size` | body bytes for read/write; encrypted |
| `0x18` | 8 | `Address` | target VA for read/write; encrypted |
| `0x20` | 8 | `Nonce` | 64-bit per-request counter; MAC input |
| `0x28` | 16 | `Mac` | 128-bit SipHash-2-4 tag |
| `0x38` | 8 | `SessionId` | client-generated session ID; MAC input |
| `0x40` | ... | body | up to `0xFFC0` bytes; ChaCha20-encrypted |

`PostboxHeader` is `alignas(8)`, `sizeof == 0x40`; the body starts at `PostboxDataAt = 0x40`.

### 3.2 Operations

| Op | Value | Behavior |
|---|---|---|
| `pb_ping` | 1 | `Status = 0`; liveness/ACK check |
| `pb_read` | 2 | copy `Size` bytes from target `Address` into the body |
| `pb_write` | 3 | copy `Size` bytes from the body to target `Address` |
| `pb_stop` | 4 | ACK, cancel the timer, flush DPCs, remove the NMI gate |
| `pb_nmi` | 5 | NMI builds only: `Size = 0`; `Address = 0` returns the tick count, `Address = 1` installs the constructed IDT, sends one self-IPI, returns the handled self-test count, and restores the Windows IDT in the same work item. Other `Address` values -> `0xC000000D`. |

`Status` values produced for authenticated requests: `0` success, `0xC0000005` access violation,
`0xC000000D` invalid parameter. An unknown `Op` or bad `Size` is rejected before a response (client
timeout), not ACKed with `0xC0000010`; `0xC000000B` is not produced by this driver.

Address policy: reads and writes are self-process only (the mailbox owner) and the whole range must
stay below `0x0000800000000000` (`Address + Size <= 0x7FFFFFFFFFFF`); a kernel-address or
cross-process op is rejected with `0xC000000D`. This is deliberate: the channel is a process-local
transport, not an arbitrary-process or kernel R/W primitive. Cross-process access would need an
allowlist and an explicit policy change; the MAC authenticates the session but does not widen the
address policy.

### 3.3 Bootstrap (`PostboxConfig`)

| Offset | Size | Field |
|---|---|---|
| `0x00` | 4 | `Magic` (`0x50424F58`, "PBOX") |
| `0x04` | 4 | `Version` (3) |
| `0x08` | 4 | `Pid` (mailbox owner) |
| `0x0C` | 4 | `Reserved` |
| `0x10` | 8 | `MailboxVa` (user VA) |
| `0x18` | 32 | `Key` (client master key; derives ChaCha/SipHash keys) |
| `0x38` | 8 | `CreateTime` (required client process creation time) |
| `0x40` | 8 | `SessionId` (client-generated) |
| `0x48` | 16 | `Reserved2` |

`sizeof(PostboxConfig) == 0x58`. The client writes a `PostboxHandoff` at `MailboxVa + 0x40` before
printing its PID/VA: magic `PBK1` (`0x314B4250`), version 1, `SessionId`, `CreateTime`, and `Key[32]`.
The loader reads it with `ReadProcessMemory` (after `GetProcessTimes`), copies the key/session/create
time into the config, and wipes its local copy. The driver derives the ChaCha20/SipHash keys and wipes
the master; the client zeroes the handoff after the first authenticated ping. The loader allocates the
config in kernel pool (`KfHeapAllocData`), passes its VA as `arg2`, and wipes/frees it after `CallEntry`
returns. `DriverEntry` copies it into `PostboxCfg`; it never retains the loader's pointer. The magic is
a type check for the bootstrap argument only; the mailbox carries a temporary PBK1 handoff during bootstrap, then the client zeroes it, so there is no persistent magic. This is
a one-time bootstrap with no runtime discovery object. `CreateTime` is filled from `GetProcessTimes`
and compared with `PsGetProcessCreateTimeQuadPart` on every poll, so a recycled PID is rejected.

`mapload --postbox <pid> <va>` is the lab front end for this. The `POSTBOX_CHANNEL` build is
manual-map only: on the SCM path the second argument is a `UNICODE_STRING` and `PostboxStart` is not
called.

### 3.4 Content protection

`PostboxCrypto.h` implements ChaCha20 (RFC 8439) and SipHash-2-4. The client derives
`ChaChaKey[32] | SipKey0[16] | SipKey1[16]` from the 32-byte master with one ChaCha20 block
(counter 0, zero nonce), writes the `PBK1` handoff, and wipes the master. The driver repeats the KDF,
wipes the master, and keeps only the derived keys.

- Header block: `Op/Pid/Size/Address` (20 bytes at `0x0C`) are ChaCha20-encrypted under
  `(SessionId ^ 0x80000000) || Nonce64`.
- Body: encrypted under `SessionId || Nonce64`; a request body only for `pb_write`, a response body
  only for `pb_read`.
- Request tag: `0x11` domain/version, `SessionId`, `Seq`, `Nonce64`, `BodyLen`, the sealed 20-byte
  header, and the body for a write. Response tag: `0x21`, `SessionId`, `Seq`, `Ack`, `Status`,
  `Nonce64`, `BodyLen`, and the body for a read.
- The driver decrypts the header into a scratch only to learn `Op`/`Size`, bounds-checks them, verifies
  the tag over the sealed header/staged body, and only then acts. A failure writes no `Ack` and does
  not advance state.
- The write body is staged in `PostboxStage` before MAC/decrypt/write; the read result is staged and
  `Seq` is re-read before publishing `Mac/Status/Ack`.
- `Seq`/`Ack`/`Status` stay plaintext for the lock-free poll; the MAC covers them. The response order
  is `Mac`, `Status`, `Ack` with release fences.

This is authenticated transport, not a trust boundary: a kernel AC or in-process DLL can read the
keys and plaintext. A same-user writer without the key can still corrupt the mailbox and cause DoS.

## 4. Kernel implementation

File: `Engine-ci/Driver/Postbox.cpp`. It is included by the unity build and is compiled only when
`POSTBOX_CHANNEL` is defined.

### 4.1 Resolve

`PostboxResolve` uses `FindFuncExportsBatch` on `GetNtoskrnl()` for:

`KeInitializeTimerEx`, `KeInitializeDpc`, `KeSetCoalescableTimer`, `KeCancelTimer`,
`KeFlushQueuedDpcs`, `ExQueueWorkItem`, `PsLookupProcessByProcessId`, `ObDereferenceObject`,
`KeDelayExecutionThread`, `KeStackAttachProcess`, `KeUnstackDetachProcess`,
`PsAcquireProcessExitSynchronization`, `PsReleaseProcessExitSynchronization`,
`PsGetProcessCreateTimeQuadPart`.

The names are stored ROT1-encoded and decoded into a stack buffer that is wiped after the resolve, so
the image does not carry the plaintext export strings. All are direct ntoskrnl exports on the target
build; a missing export fails the start rather than half-arming the timer.

### 4.2 Start

`PostboxStart` validates the config magic/version (3), `Pid`, a nonzero `CreateTime`, a nonzero
`SessionId`, the mailbox range (`MailboxVa + PostboxBytes < 0x800000000000`, 8-byte aligned), and a
nonzero key. It copies the config, derives the ChaCha20/SipHash keys from `Key`, wipes the master,
initializes the work item fields, initializes the timer and DPC, sets `PostboxRunning`, and arms 4 ms:

```cpp
PostboxArm(4, 1);       // 4 ms period, 1 ms coalescing tolerance
```

In a `POSTBOX_NMI` build the constructed-IDT gate is **not** installed at start. It is installed
only for a `pb_nmi Address=1` self-test, which runs the self-IPI and restores the Windows IDT in the
same work item. A failed install returns `0xC0000001` for that request; it does not leave a private
IDTR behind. `PostboxCancel` (used by `pb_stop`, `PostboxStop`, and the watchdog) still calls
`PostboxNmiUninstall` as defence in depth.

`KeSetCoalescableTimer` may coalesce the 4 ms period to the 15.6 ms clock tick on some systems; measure
the timer period/round trip rather than assuming 250 work items/s. A failed `PostboxResolve` wipes the
copied config before returning. The magic/version validates the **contents** of `arg2`, not the
pointer: a bogus manual-map `arg2` is dereferenced before any check, so the loader is trusted input.

### 4.3 DPC and work item

```cpp
static void PostboxDpcRoutine(void*, void*, void*, void*)
{
    if (!__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) return;
    if (__atomic_exchange_n(&PostboxInFlight, 1, __ATOMIC_ACQ_REL) == 0)
        ExQueueWorkItem(&PostboxWorkItem, DelayedWorkQueue);
}

static void PostboxWorkRoutine(void*)
{
    if (__atomic_load_n(&PostboxRunning, __ATOMIC_ACQUIRE)) PostboxPoll();
    __atomic_store_n(&PostboxInFlight, 0, __ATOMIC_RELEASE);
}
```

A periodic timer's DPC can run on two CPUs at once; the interlocked exchange makes sure only one work
item is queued. `DelayedWorkQueue` is used (variable priority), not `CriticalWorkQueue` (real-time).

### 4.4 Poll

`PostboxPoll` runs at `PASSIVE`:

1. `PsLookupProcessByProcessId(PostboxCfg.Pid, &MailboxProcess)`; drop and return on failure. Compare
   `PsGetProcessCreateTimeQuadPart(MailboxProcess)` with the required `PostboxCfg.CreateTime`; a PID
   reused by another process is rejected instead of being attached at the old mailbox VA.
2. `PsAcquireProcessExitSynchronization(MailboxProcess)`; on `STATUS_PROCESS_IS_TERMINATING` the
   acquire failed, so dereference and idle without attaching or releasing. Otherwise
   `KeStackAttachProcess(MailboxProcess, &ApcState)`, then `MailboxCr3` from
   `_KPROCESS::DirectoryTableBase`.
3. Read the sealed `PostboxHeader` with `AccessVirtualMemory`.
4. If `Seq` is not exactly `LastSeq + 1` (wrap-safe), or `SessionId` differs from the configured
   session, or `Nonce <= LastNonce`, count an idle tick; detach; return. A same-`Seq` request is
   considered only for an authenticated `pb_stop` (the client reuses the last `Seq` after a lost
   response), so a timed-out stop works whether the original request was processed or not.
5. Copy the header to a scratch and `OpenRequestHeader` it **only** to learn `Op`/`Size` for MAC
   coverage. Bounds-check `Size` and do not act on the decrypted values yet.
6. For `pb_write`, copy the body ciphertext into the static `PostboxStage`; compute the request tag over
   the original sealed header and staged body and compare it constant-time. A failure does not advance
   `LastSeq`/`LastNonce` and does not write `Ack`.
7. Only after the tag verifies, trust `Op`/`Size`/`Address`: read/write uses `CopyVirtualMemory` with
   `MailboxCr3`; write decrypts the staged body and copies from the stage, read copies into the stage
   and seals the response body there.
8. Re-read `Seq`; if the client has moved on, drop the response. Otherwise write `Mac`, `Status`, `Ack`
   in that order (body first for a read), with release fences.
9. `KeUnstackDetachProcess`, then release the exit synchronization and dereference the process.

The request MAC covers the sealed 20-byte header and, for a write, the body ciphertext; the response
MAC covers `Seq/Ack/Status/Nonce` and, for a read, the response body ciphertext. The client verifies
the response tag before trusting `Status` or decrypting. Staging the body before MAC/decrypt removes
the write-path TOCTOU where a same-process writer could swap ciphertext blocks between verify and use.

The attach exists because the mapped profile is `NO_MAP_TABLE`: the manual walk claims a free PTE in
the current process, and the client's user page tables are a usable context. The worker detaches before
it drops the mailbox reference. The copy still avoids `MmCopyVirtualMemory` and the ETW-TI read/write
syscall path; the price is a transient context switch per poll.

### 4.5 Timing

- Active: 4 ms requested, 1 ms tolerance; measure, it may coalesce to 15.6 ms (~64/s).
- After 500 idle ticks (~2 s at 4 ms, ~7.8 s at the 15.6 ms clock), the work routine re-arms at 250 ms
  with 50 ms tolerance.
- Lookup failures and header-read failures count toward the same idle counter, so a dead client drops
  to 250 ms instead of staying at 250 polls/s. The timer is still armed; a dead client cannot send
  `pb_stop` because the poll must look it up and attach to read the mailbox.
- The next request re-arms 4 ms before it is processed, so command latency returns immediately --
  provided the PID still resolves to the same process/VA.
- The timer is coalescable; the exact interval varies within `Period +/- Tolerance`.

### 4.6 Teardown

- `pb_stop`: ACK, `PostboxCancel` (`PostboxRunning = 0`, `KeCancelTimer`,
  `KeFlushQueuedDpcs`, `PostboxNmiUninstall` in an NMI build), then the work routine clears
  `PostboxInFlight`. The stop is read **inside** the poll, after `PsLookupProcessByProcessId` +
  `KeStackAttachProcess`, so it is not "before any target work": a dead client cannot stop the timer,
  and the same process/VA must survive to reconnect.
- `PostboxStop` (SCM `DriverExit`): the same cancel, then wait up to 1 s for `PostboxInFlight` to
  clear, then wipe the config and derived keys. On timeout it still wipes while a worker may be
  running; the config is small and the race is documented, not eliminated. It calls
  `PostboxNmiUninstall` even on a second stop after the timer was already cancelled.
- A manual map has no unload callback, so `pb_stop` is the only clean teardown. Without it the timer
  runs until the watchdog fires or the machine reboots, and the image must never be freed. A dead
  client cannot send `pb_stop` because the poll must look it up and attach to read the mailbox.
- A failed-poll watchdog cancels the timer after 240 failures at the 250 ms backoff (~60 s): lookup
  failure, create-time mismatch, acquire failure, repeated header-read failure, or repeated
  far-ahead/wrong-session/bad-Op/bad-MAC requests. It wipes the config, removes the NMI gate, and
  keeps the image. A client suspended longer than that needs a remap.
- `mapload --free` is refused for every payload in this prototype (the compatibility flags do not
  override it); a mapped channel cannot prove its worker/timer is stopped. Freeing under an armed
  timer is a use-after-free.

### 4.7 Failure behavior

- No logging in the poll/DPC path in release builds; a failed lookup or copy is retried on the next
  tick.
- A malformed/replayed request does not advance `LastSeq`/`LastNonce`, and a forged request without the
  session key fails the tag. A same-user writer can still corrupt `Seq`/the body and cause timeouts or
  a MAC-failure loop (DoS); it cannot forge a valid request or a valid response tag.
- The client's `Ack` timeout is the only user-visible failure; the driver never bugchecks on a missing
  mailbox page. A timeout leaves the protocol state unknown; the client should stop, not blindly retry.

### 4.8 NMI gate (`POSTBOX_NMI`)

`POSTBOX_NMI=ON` adds `PostboxNmi.cpp` and `PostboxNmi.S`. It copies the live IDT (up to 256
gates) into a 4 KiB table in the driver image, saves the Windows NMI gate, and replaces vector 2
with an interrupt gate to `PostboxNmiStub` (selector/IST copied from Windows; DPL 0; present).
The table is loaded on every active CPU with `KeSetSystemAffinityThreadEx` + `lidt` **only while a
`pb_nmi Address=1` self-test runs**; the original IDTR is saved per CPU and restored in the same
work item. The install first queries
`KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)` and refuses on more than 64 active
CPUs or any CPU outside group 0; it never partially gates a larger/grouped system.
`KeRevertToUserAffinityThreadEx` clears `SystemAffinityActive` before the system worker exits.

The assembly stub saves all general registers, clears DF for the C ABI, calls
`PostboxNmiDispatch`, then either `iretq`s (self-test consumed) or jumps to the saved
`nt!KiNmiInterrupt` with the original trap frame. The dispatcher only touches RIP-relative globals
and lock-free atomics: it increments the tick count, records the interrupted RIP/CS, and consumes
the NMI only when `PostboxNmiSelfTestPending` is set; every other NMI is chained, except an
external NMI that lands in the pending window (consumed; the self-test checks the handled RIP is in
the driver).

`pb_nmi` (`Address=0`) returns the total tick count (0 when the transient gate is not installed).
`pb_nmi` (`Address=1`) installs the gate, checks the current CPU is gated, sets the pending flag, and
sends an NMI to the current CPU: x2APIC writes ICR MSR `0x830`; xAPIC maps the APIC page with
`MmMapIoSpace`, writes ICR `0x300`, waits for the handled count to change, then unmaps and restores
the Windows IDTR. The response is the handled count; the self-test requires the handled RIP to be
inside the driver, so an idle-loop external NMI does not satisfy it. An external NMI that hits the
driver inside the pending window can still be consumed; the test is functional, not a source tag.

Removal is idempotent: `PostboxNmiUninstall` clears the active flag and restores each saved IDTR.
The gate is removed at the end of the `pb_nmi Address=1` work item, so no private IDTR survives the
request. The table and saved handler address are deliberately not wiped, so an in-flight handler
cannot jump into freed memory. `pb_stop`, `PostboxStop`, and the failed-poll watchdog still call it
as defence in depth.

Artifacts: during the transient `pb_nmi Address=1` self-test, `sidt`/IDTR points at the driver image
and vector 2 is the stub; the 4 KiB table is a static copy of the Windows IDT. The gate is removed
in the same work item, so it is not a long-lived PatchGuard risk; the feature is opt-in and the
default Postbox build keeps the unmodified Windows IDT. The xAPIC self-test also creates a brief
`MmMapIoSpace` system mapping; the x2APIC path does not. A kernel AC with R/W can read the
table/stub/counters; the gate is not a stealth boundary. See `AC-26` and
`out/vm-test/postbox-l6-20261029/`.

## 5. Client implementation

Files: `Engine-ci/User/PostboxClient.cpp`, `Engine-ci/User/PostboxOnly.cpp` (client-only
`PostboxClient.exe`), and `Engine-ci/User/main.cpp` (`--postbox` mode of the dual-client lab harness).

- Allocates 64 KiB with an OS-chosen `VirtualAlloc` base and prints the actual VA; the loader takes the
  printed value. There is no fixed `0x5A000000` in the current client.
- Generates a 32-byte master key and a 64-bit `SessionId` with `BCryptGenRandom`, writes the `PBK1`
  handoff at `Base+0x40`, derives ChaCha20/SipHash keys, and prints `pid`/`VA`; sends `pb_ping` and
  waits up to 60 s so the loader can start after the client. It zeroes the handoff after the first
  authenticated ping.
- Runs `ping`, `read` (a local `int`), `write` (the same `int`), a 0x8000-byte bulk write/read, then
  `pb_stop`. Every request is header/body sealed and MACed; every response tag is verified before
  `Status` or the body is trusted.
- No handle, no section, no named object. The test client's `Ack` poll uses `Sleep(1)`; at the default
  15.6 ms timer that is ~64 wakeups/s, and it only runs while a request is outstanding. There is no
  driver-specific syscall or API call in the loop.

## 6. Build

Default (unchanged, named-section channel):

```powershell
cmake --build Engine-ci\Driver\build-nohook-release
```

Postbox build (NMI off):

```powershell
cmake -S Engine-ci\Driver -B Engine-ci\Driver\build-postbox-release -G Ninja `
      -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_CXX_COMPILER=C:/msys64/clang64/bin/clang++.exe `
      -DPOSTBOX_CHANNEL=ON -DMAPPED_SAFE=ON -DDEBUG_BUILD=OFF
cmake --build Engine-ci\Driver\build-postbox-release
```

Postbox + NMI gate:

```powershell
cmake -S Engine-ci\Driver -B Engine-ci\Driver\build-postbox-nmi-release -G Ninja `
      -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_CXX_COMPILER=C:/msys64/clang64/bin/clang++.exe `
      -DCMAKE_ASM_COMPILER=C:/msys64/clang64/bin/clang.exe `
      -DPOSTBOX_CHANNEL=ON -DPOSTBOX_NMI=ON -DMAPPED_SAFE=ON -DDEBUG_BUILD=OFF
cmake --build Engine-ci\Driver\build-postbox-nmi-release
```

`POSTBOX_NMI=ON` calls `enable_language(ASM)` and adds `PostboxNmi.S`; the assembly is assembled
by clang's integrated assembler. `POSTBOX_NMI=ON` without `POSTBOX_CHANNEL=ON` is a configure error.
The NMI build is `POSTBOX_CHANNEL=ON` + `POSTBOX_NMI=ON`; the default named-section build is not
affected by either option.

In CLion, add a CMake profile with `POSTBOX_CHANNEL=ON`, `POSTBOX_NMI=ON`, and `MAPPED_SAFE=ON`
instead of using the CLI.

`POSTBOX_CHANNEL=ON` excludes `Channel.cpp` from the unity build entirely, so the section code and the
`EngineCiShared` string are not in the image. A static byte scan of the built driver confirms:
`EngineCiShared`/`ECI1` absent in the Postbox build, present in the default build.

Manual-map only. The SCM path passes a `UNICODE_STRING` in `arg2`, not a `PostboxConfig`.

## 7. Lab run

```text
# guest console 1 (NMI build)
PostboxClient.exe --nmi
# prints: postbox: pid=<pid> va=0x<va>; waits up to 60 s
# after the bulk tests: nmi: count=<ticks>; nmi: self-test handled=<n>

# guest console 2
mapload.exe --sys Driver.sys --provider pte --postbox <pid> 0x<va>

# console 1: ping/read/write/nmi/stop run automatically
```

`Driver.sys` is the `build-postbox-nmi-release` output for the NMI run, or
`build-postbox-release` for the NMI-off run. Without `--sys`, `--postbox` selects
`build-postbox-release` (NMI-off); pass the NMI build explicitly for the NMI run. The loader maps it,
passes the config in `arg2`, frees the config page after the entry returns, and cleans the provider.
The client sends `pb_stop` on success (and best-effort on an error path); the timer is cancelled,
the transient NMI gate is already gone, and the payload must be remapped before another run. A client
crash leaves the timer until the failed-poll watchdog fires (~60 s) or the machine reboots.

Expected evidence (AC-25 §8):

- `!thread`: no payload system thread.
- `!vad`: only the client's heap/private region, no 1 MiB section view.
- `!pte`/`!pfn` on the mailbox: normal private page, no prototype/section.
- `!timer`: the KTIMER and the DPC pointer.
- `!pool`: no new channel allocation.
- Worker stack during the work item: `nt!ExpWorkerThread` frames plus a transient payload frame.
- NMI build only: `!idt 2` is `nt!KiNmiInterrupt` before the map and after `pb_stop`/the watchdog;
  while the gate is installed, `sidt`/IDTR points at the driver image's 4 KiB table and vector 2 is
  `PostboxNmiStub`. The self-test is proven by `nmi: self-test handled=1`, not by the tick delta.

**Live result (2026-10-29, 19041 clone):** the NMI build (27,648 bytes, `entryRva=0x479C`,
`SizeOfImage=0xB000`, SHA-256 `ab909f65...`) returned entry success with
`postbox: pid 4592 mailbox 0x1A0000`; the client reported `ping`, `read`, `write`, an invalid read
(`0xC0000005`), `nmi: count=0`, `nmi: self-test handled=1`, `stop`, and a `0x8000`-byte bulk
write/read all as expected (`read: x=1111 y=1111`, `write: x=4242 y=4242`, `bulk read: match=1`).
The NMI-off build (25,600 bytes, `entryRva=0x3F31`, SHA-256 `0f0a5caa...`) passed the same six
operations without the NMI op. A corrupted `PBK1` key produced no ACK and a client auth failure;
after the watchdog, `!idt 2` was back on `nt!KiNmiInterrupt`; the NMI gate is transient, so `r idtr` is Windows after the self-test. The mapper skips `.pbox`, so the mapped image has no `PBOXABI` marker. The request/response MAC and ChaCha20
header/body path are live; the client generated the key/session and the loader consumed the `PBK1`
handoff. An earlier build failed the header read because `AccessVirtualMemory`'s `NO_MAP_TABLE` PTE
claim ran in the System process; attaching the worker to the mailbox process fixed it. The
`!timer`/`!thread`/`!vtop` transcript is in `out/vm-test/postbox-l6-20261029/kd-final.txt`; the
timer/DPC are in the driver image, `KTIMER.Period=4 ms`, and raw `KTIMER.Dpc` is encoded on 19041.
Evidence: `out/vm-test/postbox-l6-20261029/`.

## 8. Current limitations

1. **Authenticated transport, not a trust boundary.** The request header fields and body are
   ChaCha20-encrypted; every request/response carries a 128-bit SipHash-2-4 tag; the master is a
   client `BCryptGenRandom` value handed to the loader as `PBK1`, derived in the driver, and wiped.
   A kernel AC or an in-process AC DLL can read the key, the stage, and the plaintext. A same-user
   writer can still corrupt the mailbox and cause timeouts/MAC-failure loops (DoS). The stage and
   header buffers are wiped before return; the mailbox remains until the client zeroes it.
2. **Self-process only; PID identity is create-time bound.** The target is the mailbox owner;
   `Header.Pid` is ignored. `PostboxCfg.CreateTime` is filled by the loader and compared with
   `PsGetProcessCreateTimeQuadPart` on each poll, so a recycled PID is rejected. The MAC authenticates
   the session, but a same-user writer can still DoS by corrupting the mailbox. Cross-process access
   needs an allowlist and a separate policy decision.
3. **`User.exe` contains both clients; `PostboxClient.exe` does not.** The lab harness still carries
   `EngineCiShared`/`ECI1`; the client-only build links `PostboxOnly.cpp` + `PostboxClient.cpp` and has
   no old-channel strings. Use it for deployment tests.
4. **Lab-VM E3/E4 pending.** The `pre-driver-tests` snapshot cannot restore because
   `Windows 10 x64-Snapshot1.vmem` is missing; `vmrun start` aborts and the snapshot was not modified.
   The live run in §7 used the running 19041 clone, not that snapshot; the stack-sampling and
   timer-table experiments still need a bootable lab VM.
5. **Residual artifacts.** The armed `KTIMER`, the transient worker frame, the per-poll
   `KeStackAttachProcess` context switch, and the transient client PTE claimed by `AccessVirtualMemory`
   are inherent to this design; AC-25 §6 covers their detection risk. The payload image remains the
   dominant problem (AC-12/AC-13): an unbacked executable image is caught regardless of the channel.
6. **No HVCI path.** The design needs executable payload code; on HVCI the channel is moot.
7. **`--free` is disabled.** `mapload --free` is refused for every payload; the
   `--free-unsafe`/`--free-known-safe` flags are compatibility-only. A default-channel or Postbox
   payload cannot prove its thread/timer is stopped, so freeing it is a use-after-free.
8. **`arg2` is still build-selected.** `PostboxConfig` carries a magic and version, so the contents
   are validated, but the pointer itself is trusted and dereferenced before the check. A proper
   versioned `Bootstrap` struct is the next step if the loader ever needs to carry both a provider
   name and the channel config. The loader's config allocation is small pool (`Ntfs`, 0x58 bytes),
   wiped and freed after `CallEntry` in the current build; the driver .data copy remains until `pb_stop`.

9. **NMI gate is a transient IDT/IDTR artifact.** During `pb_nmi Address=1`, `sidt` returns the
   constructed 4 KiB table in the driver image and vector 2 is `PostboxNmiStub`; the Windows IDT is
   restored in the same work item. The gate is opt-in and is not present at rest, so it is not a
   long-lived PatchGuard risk. The default Postbox build never changes the IDT. A kernel AC with R/W
   can read the table/stub/counters; the gate is not a stealth boundary.
10. **NMI self-test is xAPIC/x2APIC-specific and group-0-only.** The xAPIC path briefly maps the
    APIC page with `MmMapIoSpace`; x2APIC writes ICR MSR `0x830`. The install uses
    `KeSetSystemAffinityThreadEx`, so only group-0 active CPUs are covered; install refuses >64 CPUs
    or any group >0, and CPU hot-add after install is not handled. The lab has 2 vCPUs.
11. **NMI tick count includes external NMIs.** The lab/KD delivered periodic NMIs at
    `nt!HalProcessorIdle+0xf`; these are chained to Windows (except one that lands in the self-test
    pending window). `pb_nmi` self-test returns the handled count and requires the handled RIP to be
    inside the driver (`in-driver 1`), so it rejects the idle-loop case; do not use the tick delta as
    a source proof.

## 9. Review outcomes

An independent review of the first build found three P0 issues and several P1s. The current tree
contains these fixes:

| Finding | Status |
|---|---|
| KDPC declared 0x38; real x64 KDPC is 0x40 with `ProcessorHistory` at +0x10 | fixed; asserts on size and offsets; live test rerun |
| Address check only tested the start; a copy could cross `0x800000000000` into the PML4[256] alias | fixed: whole-range check below the user limit, self-process only; mailbox base range checked at start. A canonicality guard inside `Mem.cpp::GetPhysicalAddress` is still a good defense-in-depth change |
| Writes could overlap the mailbox's 0x40 header and clobber `Seq/Ack/Status` | fixed: `pb_write` ranges that overlap the header are rejected with `0xC000000D` |
| Header/4 KiB body remained on the worker stack | fixed: volatile wipe before return; pointer/frame residue remains |
| Fixed key ramp / fixed test VA | fixed: OS-chosen mailbox VA; client CSPRNG master + `PBK1` handoff; ChaCha20/SipHash derived and wiped |
| `invlpg` only before the claimed access, not after release | fixed: `invlpg` after `ReleaseEntry` in the dedicated and search paths |
| `mapload --free` freed the image under the default channel's system thread | fixed: `--free` is refused for every payload; the old flags are compatibility-only; README/usage updated |
| Response wrote the whole header and `Ack` could precede `Status` | fixed: `Mac` then `Status` then `Ack` with release fences; request fields are never written back |
| `pb_stop` required a live target lookup | partial: stop is handled before the target read/write, but the poll still looks up and attaches to read the mailbox; a dead client cannot stop the timer |
| Idle backoff unreachable on lookup/header failure | fixed: failures feed the same idle counter |
| Client timeout paths skipped stop and did not assert results | fixed: best-effort stop, status/value checks, nonzero exit on mismatch |
| Only the first mailbox page was faulted; large transfers failed | fixed: client touches all 64 KiB; 0x8000-byte bulk round trip passes |
| Forged future `Seq` / client restart | fixed for replay/desync/forgery: only `LastSeq + 1`, the configured `SessionId`, and a higher `Nonce` are accepted; the MAC rejects a request without the key. A crashed client still needs a remap |
| Process exit could tear down page tables during the walk | fixed: `PsAcquireProcessExitSynchronization` returns `STATUS_PROCESS_IS_TERMINATING` when rundown is active; on failure the driver dereferences and idles without attaching or releasing |
| Timer armed before `LinkMapTable`/PE-header cleanup | fixed: `PostboxStart` is step 6, at the end of `DriverEntry` |
| `arg2` type confusion | mitigated: `PostboxConfig` has a magic + version and is 0x58 bytes; a versioned `Bootstrap` struct is the next step |

Remaining, deliberately: the per-poll attach and transient client PTE are residual artifacts; `User.exe` carries both clients; the NMI build's constructed IDT exists only during `pb_nmi Address=1`; E3/E4 need a bootable lab VM; the tamper-negative test on the pre-marker build is superseded by the current run. The review's P2 items
(stack budget, `PostboxStop` dead path, second-stop idempotence, config-page leak on a killed paused
run) are documented in the relevant sections and are not fixed in the prototype.

## 10. File map

| File | Role |
|---|---|
| `Engine-ci/Common/Postbox.h` | mailbox/config layouts, opcodes, size assertions |
| `Engine-ci/Driver/Postbox.cpp` | timer, DPC, work item, poll, start/stop |
| `Engine-ci/Driver/main.cpp` | `POSTBOX_CHANNEL` branch in `DriverEntry`/`DriverExit` |
| `Engine-ci/Driver/CMakeLists.txt` | `POSTBOX_CHANNEL` option |
| `Engine-ci/User/PostboxClient.cpp` | user-side protocol and test sequence |
| `Engine-ci/User/main.cpp` | `--postbox` mode |
| `mapload/main.cpp` | `--postbox <pid> <va>` config page |
| `mapload/README.md` | loader flag |
| `out/research/AC-25_channel.md` | threat model, alternatives, sensor matrix, experiments |

## 11. References

- `out/research/AC-25_channel.md` — full detection analysis and experiment plan.
- `out/research/AC-12_execution_backing.md`, `AC-13_module_list.md` — why the image, not the channel,
  is the main bound.
- Microsoft: `KeSetCoalescableTimer`, `ExQueueWorkItem`, `KeFlushQueuedDpcs`,
  `PsLookupProcessByProcessId`.
- `mapload/scripts/kd_breakpoints.txt`, `Engine-ci/AGENTS.md` — live-debug rules.
