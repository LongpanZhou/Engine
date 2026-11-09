# Engine

Design notes for the Engine-ci driver, written from an anti-cheat perspective:
what the design removes, what it only shortens, and what it cannot avoid.

Engine-ci is a manually mapped, one-shot Windows x64 kernel payload. A loader
maps a headerless image, calls its entry once with a sealed job batch, and frees
the image when the entry returns.

```
loader -> signed provider (kernel VA read/write)
       -> headerless image in global-PTE pages
       -> relocations + ntoskrnl imports
       -> sealed batch in an unnamed pagefile section
       -> KAPC in the loader's own thread
       -> DriverEntry -> jobs run inline -> seal results -> wipe/free
```

## Why this design

The goal is to leave no persistent kernel object to enumerate. There is no
service, driver object, device, IOCTL, module-list entry, kernel thread, timer,
DPC, work item, state page, or unload path. The only kernel execution is the
entry call, on the loader's own thread; the image exists only for the batch.

This is a trade: fewer post-load artifacts, but a short and observable execution
window, and a hard dependency on a signed kernel read/write provider.

## What is good

- **No dedicated kernel thread.** The batch runs inline in the loader thread
  through a manually built KAPC. There is no `PsCreateSystemThread`, no thread
  object, no thread-list entry, no start address, and no worker/DPC/timer
  cadence to sample.
- **No service or driver object.** The image is manual-mapped and the job build
  refuses a normal SCM load. There is no service key, `\Driver\...` object,
  `DriverObject`, `DriverSection`, or unload callback.
- **No persistent state.** One map, one entry, N jobs, one teardown. The image,
  config page, and job section are wiped and freed after the entry. There is no
  pool allocation, state page, mailbox, or reaper to find later.
- **No device or IOCTL.** The job transport is an unnamed pagefile-backed
  section, not a device object, symbolic link, named pipe, or registry key.
- **No import table or hooks.** The job image has no imports; the loader
  supplies the image layout and ntoskrnl base. There are no SSDT, IDT, inline,
  or notify-routine hooks, so PatchGuard exposure is low.
- **Direct memory access.** The driver walks the target CR3 itself and copies
  through its own page-table path. It does not call `MmCopyVirtualMemory`, does
  not attach to the target process, and takes no target handle or object
  reference.
- **Headerless image.** No MZ/PE header, no section table, stripped import
  metadata, and zeroed `.reloc`/`.pdata`. Naive PE-header and module-list scans
  find nothing.
- **W^X image.** `.text` is RX, writable sections are RW/NX, and everything else
  is R/NX. There is no RWX image page.
- **Sealed transport.** Target VAs, sizes, and read/write data are ChaCha20
  encrypted and SipHash-2-4 authenticated. The master key is erased at each hop.

## What it cannot avoid

- **Memory page scan.** The image must be resident and executable while it
  runs. A headerless image defeats header signatures, not code scanning. A scan
  for private or unbacked executable pages, a PTE/PFN audit, or a code-signature
  scan can still find it. The image is not encrypted.
- **Image backup and integrity checks.** The design does not patch game or
  module code, so backup-and-compare checks on legitimate images should not flag
  it. It does appear as an executable region with no module, control area, or
  prototype PTE backing, which is its own signal. Missing unwind metadata also
  makes stackwalk and unwind validation see unbacked frames.
- **Page-table artifacts.** The global-PTE mapping writes PTEs through the
  KUSER_SHARED_DATA PT window and depends on the self-map and PFN database. PTE
  audits, PFN validation, self-map checks, and permission-transition checks can
  see the mapping while it exists.
- **Thread and stack.** No thread removes a thread object, not the execution
  context. The code runs on the loader's thread, and kernel stack return
  addresses point into the mapped image, outside any known module. Stack
  sampling, NMI/APC stackwalks, return-address validation, LBR/PMI, and unwind
  checks can catch that.
- **Provider chain.** Kernel VA access needs signed vulnerable drivers. Their
  services, devices, handles, IOCTLs, service-install events, image-load
  telemetry, and blocklist status are visible at the provider layer.
- **Loader and user mode.** The loader is an elevated process with a command
  line, a child process, an inherited section handle, a pagefile-section VAD,
  and plaintext strings. Prefetch, Amcache, ETW, and handle enumeration see it.
- **HVCI / VBS.** The design cannot execute under HVCI. Enabling memory
  integrity is a hard counter; the design also assumes specific Windows 10 x64
  layouts and a non-HVCI target.
- **Crash and forensics.** A bugcheck or dump can preserve the image, stack, and
  section contents. One-shot execution does not guarantee no residue.
- **Timing.** The batch and map/free burst is short, but it is still a window.
  There is no persistence; there is still a moment when everything is present.

## Communication system

The controller creates an unnamed pagefile-backed section, writes a small
header, a sealed `PostboxJobBatch`, and sealed per-job data regions, then starts
one loader child with the inherited handle. The child maps the section,
validates the header, wipes the key copy, builds the `PostboxJobConfig` page,
and inserts a KAPC into its own thread. The driver copies the batch to its
stack, verifies the MAC before decrypting, runs each job inline, seals the result
batch, and returns. The loader then opens the sealed results, wipes the section,
and frees the image.

Limits: 32 jobs per batch, 64 KiB per job, 1 MiB per section.

This avoids a named device, IOCTL surface, registry key, and persistent channel,
and keeps plaintext target addresses and data out of the section. It does not
hide the section object, its handle, its VAD, the child process, or the brief
key lifetime.

## Memory management

The provider gets kernel VA read/write from three vendor-signed drivers through
a user-mode PTE window. The image is backed by locked user pages mapped into the
KUSER_SHARED_DATA PT window, so it never goes through `ExAllocatePool`, carries
no pool tag, and does not appear in BigPool. The loader writes the image through
the user alias and applies the section permissions per page.

Inside the payload, the memory layer walks PML4/PDPT/PD/PT with the target CR3,
maps physical pages through empty PTEs, and copies in 0x400-byte stack chunks.
It reads the current process from KPCR instead of importing
`PsGetCurrentProcess`, and resolves cross-process targets by walking the process
list. Only present pages are handled; it does not fault pages in.

This avoids pool-tag/size scans, module-loader accounting, import-table scans,
process attach, and `MmCopyVirtualMemory` telemetry. The cost is a dependency on
the signed provider, PTE and page-table artifacts, non-HVCI execution, and
resident target pages.

## Detection summary

| Area | Result |
|---|---|
| Service, driver object, module list | Removed by manual map |
| Thread, timer, DPC, work item | Removed; inline stack frames remain |
| Device, IOCTL, registry | Removed; section and handle remain |
| Persistent pool or state page | Removed; batch window remains |
| Import table and nt hooks | Removed; code and strings remain |
| Header and section table | Removed; memory page scan still works |
| HVCI / VBS | Hard counter; design does not run |

## Development-only driver

The Engine-ci driver is development-only. It is built for manual mapping,
refuses a normal SCM load, has no unload path, and is not production-ready. Use
it only in isolated lab VMs or on systems you are authorized to test.

This document is a design and detection review, not a guarantee against any
specific anti-cheat product.
