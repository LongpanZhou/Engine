#pragma once

// Every string the driver uses at runtime, stored encoded so the plain text does not appear in Driver.sys.
// Decode each one where it is used, for example: EnumerateEProcess(Decode(UserExeName).data())
//
// Include this after Crypt.cpp and Scan.cpp, which provide Encode/Decode/EncodeBytes and PatternToBytes.
// Debug messages (print(...)) are not listed here: print() compiles to nothing in release builds.

// The bytes that identify NtCompareSigningLevels in ntoskrnl (? is a wildcard). Stored encoded, like the strings below,
// so the pattern is decoded with the same SEED it was encoded with
constexpr auto Signature = EncodeBytes(PatternToBytes("4C 8B 05 ? ? ? ? 33 C0 4D 85 C0 74 ? 49 8B C0 E8 ? ? ? ? F7 D8"));

// Names searched for at runtime
constexpr auto UserExeName = Encode(L"User.exe");
constexpr auto NtoskrnlName = Encode("ntoskrnl.exe");
constexpr auto PageSectionName = Encode("PAGE");

// Trace-cleaning search targets
constexpr auto TextSectionName = Encode(".text");
constexpr auto CiDllName = Encode(L"ci.dll");

// Exported routine/symbol names the trace cleaners resolve by hand through the export directory
// (no import table entries; data exports come back as the variable's address)
constexpr auto ExAcquireResourceName = Encode("ExAcquireResourceExclusiveLite");
constexpr auto ExReleaseResourceName = Encode("ExReleaseResourceLite");
constexpr auto ExFreePoolTagName = Encode("ExFreePoolWithTag");
constexpr auto RtlRandomExName = Encode("RtlRandomEx");
constexpr auto PsLoadedModuleResourceName = Encode("PsLoadedModuleResource");

// Byte signatures that reach the trace globals from the reference 64KernelDriverCleaner (wildcard ?).
// Stored encoded like every other string; used via Decode(...).data() as a SignatureScan byte string

// The PiDDB housekeeping list head (nt!PiDDBCacheList), through the block in nt!PiLookupInDDBCache
// that threads a fresh entry onto the list tail: `lea rdx,[head] / mov rcx,[head->Blink] / cmp
// [rcx],rdx` — the Rtl InsertTailList shape. Unique in the whole image (verified against the live
// 19041 kernel) and located in PAGE, which ScanModuleImage searches first
constexpr auto PiDDBCacheListSignature = EncodeBytes(PatternToBytes(
    "48 8D 15 ? ? ? ? 48 8B 0D ? ? ? ? 48 39 11"));
constexpr auto MmUnloadedDriversSignature = EncodeBytes(PatternToBytes("4C 8B 15 ? ? ? ? 4C 8B C9"));
constexpr auto MmLastUnloadedDriverSignature = EncodeBytes(PatternToBytes("8B 05 ? ? ? ? 83 F8 32"));
constexpr auto KernelHashBucketListSignature21H1 = EncodeBytes(PatternToBytes(
    "4C 8D 35 ? ? ? ? E9 ? ? ? ? 8B 84 24"));
constexpr auto KernelHashBucketListSignature22H2 = EncodeBytes(PatternToBytes(
    "48 8B 1D ? ? ? ? EB ? F7 43 40 ? 20 ? ?"));

// 'mov rdx, imm64; shl rdx, 19h' inside MmGetVirtualForPhysical, where the imm64 IS PTE_BASE (GetPteBase
// reads it at match + 2). The bytes at match + 10..13 are the shl opcode and its displacement byte 0x19
constexpr auto PteBaseSignature = EncodeBytes(PatternToBytes("48 BA ? ? ? ? ? ? ? ? 48 C1 E2"));

// 'mov rax, imm64; mov rax, [rax+rdx*8]; shl rax, 19h' inside MmGetVirtualForPhysical. The imm64 is the PfnDatabase
// PteAddress column (GetPfnPteAddressBase reads it at match + 2); the shl displacement sits at match + 17
constexpr auto PfnPteAddressSignature = EncodeBytes(PatternToBytes("48 B8 ? ? ? ? ? ? ? ? 48 8B 04 D0 48 C1 E0 19"));