// ---------------------------------------------------------------------------
// Engine-ci/tests/host/driver_tests.cpp
//
// Host-side unit tests for the freestanding/pure code of Engine-ci/Driver:
//   * Lib/structs.h + Lib/utils.h   (unity preamble, minus kernel-only files)
//   * Crypt.cpp                     (compile-time string codec: XorSeed,
//                                    Encode/Decode, EncodeName, EncodeBytes)
//   * Scan.cpp                      (pattern parser + string/byte helpers +
//                                    SignatureScan over synthetic buffers)
//
// These fragments are not kernel-bound: they compile as one translation unit
// with the same include order Driver main.cpp uses. No kernel memory access
// happens here.
//
// IMPORTANT: unit tests, debug-only in spirit — this target is compiled only
// by scripts/run-unit-tests.ps1; it is not part of the driver build and never
// ships.
//
// No external framework: micro harness of CHECK() counters, exit code
// 0 == all green.
// ---------------------------------------------------------------------------

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

// --- driver unity preamble (mirrors main.cpp, minimal subset) --------------

#include "../../Driver/Lib/structs.h"
#include "../../Driver/Lib/utils.h"

using namespace arch;
using namespace intrin;

#include "../../Driver/Crypt.cpp"
#include "../../Driver/Scan.cpp"

// DEBUG builds instantiate print() -> win::print_ex -> DbgPrintEx. The host
// test has no kernel print sink; a no-op definition keeps the DEBUG-mode link
// working (the test asserts values, it does not read log output).
extern "C" win::ntstatus DbgPrintEx(std::uint32_t, std::uint32_t, const char*, ...)
{
    return static_cast<win::ntstatus>(0);
}

// Scan.cpp's DEBUG-only VerifyFindFuncExports references the loader-resolved
// import slots; the host test provides storage so the fragment links. The
// self-test itself is never called on the host.
static void* g_HostPsInitialSystemProcess = nullptr;
static void* g_HostPsLoadedModuleList = nullptr;
extern "C" void** __imp_PsInitialSystemProcess = &g_HostPsInitialSystemProcess;
extern "C" void** __imp_PsLoadedModuleList = &g_HostPsLoadedModuleList;

// Unity order continues like main.cpp: Strings.h (encoded names/patterns) and
// Locate.cpp (ScanModuleImage + ResolveRipRelative) sit after Scan.cpp.
#include "../../Driver/Strings.h"
#include "../../Driver/Locate.cpp"
#include "../../Driver/Lib/pure.h"
#include "../../Common/Command.h"

// ---------------------------------------------------------------------------
// Micro harness
// ---------------------------------------------------------------------------

static unsigned g_Pass = 0;
static unsigned g_Fail = 0;

static void Report(bool ok, const char* file, unsigned line, const char* expr)
{
    if (ok) ++g_Pass;
    else { ++g_Fail; std::printf("[FAIL] %s:%u  %s\n", file, line, expr); }
}

#define CHECK(Cond) Report((Cond), __FILE__, __LINE__, #Cond)

// address has an implicit operator uintptr_t(); use it for comparisons.
static uintptr_t AddrOf(address A) { return static_cast<uintptr_t>(A); }

// ===========================================================================
// 1. Crypt.cpp — compile-time string/bytes codec (XorSeed family)
// ===========================================================================

// The encode contract exactly as the driver's runtime decode sites rely on:
//   * PostboxResolve:  byte ^ SEED, restored into stack buffers
//   * MemDecodeName:   byte ^ SEED, restored into stack buffers
// Per name:
//   * encoded content byte != 0     (no mid-string truncation)
//   * encoded content byte >= 0x80  (defeats plain-ASCII and ROT1 scans)
//   * XOR with SEED recovers the plaintext exactly
//   * terminator stays 0
template<size_t N>
static void TestEncodeOne(const char (&name)[N])
{
    static_assert(N - 1 < sizeof(EncodedName::Bytes),
                  "name exceeds the EncodedName storage (EncodeName has no bound check)");
    const auto encoded = EncodeName(name);
    bool sawNul = false, allHigh = true, decodeOk = true;
    for (size_t i = 0; i < N - 1; ++i)
    {
        const unsigned char coded = static_cast<unsigned char>(encoded.Bytes[i]);
        if (coded == 0) sawNul = true;
        if (coded < 0x80) allHigh = false;
        if ((unsigned char)(coded ^ (SEED & 0xFF)) != (unsigned char)name[i])
            decodeOk = false;
    }
    CHECK(!sawNul);
    CHECK(allHigh);
    CHECK(decodeOk);
    CHECK(encoded.Bytes[N - 1] == '\0');   // terminator preserved
}

// The full plaintext list the driver encodes with EncodeName: PostboxResolve's
// 19 import names, MemSetPreStartNtoskrnl's two data exports, and the four NMI
// names used by the NMI gate/sanitizer. If a name is added to the driver, add
// it here; if one is removed, remove it here.
static void TestEncodeNameContract()
{
    TestEncodeOne("KeInitializeTimerEx");
    TestEncodeOne("KeInitializeDpc");
    TestEncodeOne("KeSetCoalescableTimer");
    TestEncodeOne("KeCancelTimer");
    TestEncodeOne("KeFlushQueuedDpcs");
    TestEncodeOne("ExQueueWorkItem");
    TestEncodeOne("PsLookupProcessByProcessId");
    TestEncodeOne("ObDereferenceObject");
    TestEncodeOne("KeDelayExecutionThread");
    TestEncodeOne("PsGetProcessCreateTimeQuadPart");
    TestEncodeOne("ExAllocatePoolWithTag");
    TestEncodeOne("ExFreePool");
    TestEncodeOne("MmCopyVirtualMemory");
    TestEncodeOne("KeIpiGenericCall");
    TestEncodeOne("PsGetCurrentProcess");
    TestEncodeOne("PsAcquireProcessExitSynchronization");
    TestEncodeOne("PsReleaseProcessExitSynchronization");
    TestEncodeOne("PsCreateSystemThread");
    TestEncodeOne("NtClose");
    TestEncodeOne("PsInitialSystemProcess");
    TestEncodeOne("PsLoadedModuleList");

    // NMI gate / sanitizer names (Postbox.cpp PostboxNmiResolve)
    TestEncodeOne("KeRegisterNmiCallback");
    TestEncodeOne("KeDeregisterNmiCallback");
    TestEncodeOne("KeGetCurrentProcessorNumberEx");
    TestEncodeOne("nmicallbackhandler");
}

static void TestEncodedNamesCrossDecode()
{
    // Cross-check: EncodeName's output equals the manual `plaintext ^ SEED`
    // byte transforms the runtime decode rules implement, row by row.
    const char name[] = "PsLoadedModuleList";
    const auto encoded = EncodeName(name);
    for (size_t i = 0; i < strlen(name); ++i)
        CHECK(static_cast<unsigned char>(encoded.Bytes[i]) ==
              static_cast<unsigned char>(name[i] ^ SEED));
}

static void TestXorSeedSymmetry()
{
    std::array<char, 16> plain = {};
    std::memcpy(plain.data(), "expand32bytek", 13);
    const auto encoded = XorSeed(plain);
    const auto decoded = XorSeed(encoded);
    CHECK(decoded == plain);                      // XOR is an exact involution
    // exactly N-1 elements are transformed; the trailing element is the
    // terminator and stays as-is
    size_t changed = 0;
    for (size_t i = 0; i < plain.size(); ++i)
        if (encoded[i] != plain[i]) ++changed;
    CHECK(changed == plain.size() - 1);
}

static void TestEncodeBytesRoundTrip()
{
    // Crypt.cpp's byte-array variant (Scan.cpp has a Pattern<N> overload of
    // the same name; both exist in the unity build and are resolved by
    // parameter type). XorSeed mirrors "strings end in NUL": the LAST array
    // element is never touched, so only arrays whose final byte is 0
    // round-trip. Runtime callers pass Pattern<N>, whose last byte *is* the
    // terminator.
    const std::array<char, 6> withTerm = {'\x48', '\x89', '\x5C', '\x24', '\x10', '\0'};
    const auto enc = EncodeBytes(withTerm);
    const auto dec = EncodeBytes(enc);              // XOR is its own inverse
    CHECK(dec == withTerm);
    CHECK(enc[0] == (char)(withTerm[0] ^ SEED));    // and it moved the bytes
    CHECK(enc[5] == '\0' && dec[5] == '\0');        // terminator untouched

    // DOCUMENTED QUIRK: an array with a nonzero last byte does NOT round-trip —
    // the output is value-initialized, so the untouched last element reads back
    // as 0 (the byte is effectively lost, not moved).
    const std::array<char, 2> full = {'\x48', '\xFF'};
    const auto partial = EncodeBytes(full);
    CHECK(partial[0] == (char)('\x48' ^ SEED));
    CHECK(partial[1] == '\0');                      // left as zero
}

// ===========================================================================
// 2. Scan.cpp — pattern parser, signature scan, string helpers
// ===========================================================================

static void TestHexToByte()
{
    CHECK(HexToByte('0') == 0 && HexToByte('9') == 9);
    CHECK(HexToByte('A') == 0xA && HexToByte('F') == 0xF);
    CHECK(HexToByte('a') == 0xA && HexToByte('f') == 0xF);
    CHECK(HexToByte(' ') == 0xFF);                  // documented invalid result
    CHECK(HexToByte('\0') == 0xFF);
    CHECK(HexToByte('g') == 0xFF);
}

static void TestPatternToBytes()
{
    auto p1 = PatternToBytes("AA BB 00 CD");
    CHECK(p1.Length == 4);
    CHECK(p1.Bytes[0] == '\xAA' && p1.Bytes[1] == '\xBB');
    CHECK(p1.Bytes[2] == '\x00' && p1.Bytes[3] == '\xCD');
    CHECK(p1.Bytes[4] == '\0');                     // trailing terminator written

    // single '?' token: one wildcard byte ('?' is the in-memory value)
    auto p2 = PatternToBytes("4A ? 60");
    CHECK(p2.Length == 3);
    CHECK(p2.Bytes[0] == '\x4A');
    CHECK(p2.Bytes[1] == '?');
    CHECK(p2.Bytes[2] == '\x60');

    // '??' COLLAPSES: after the first wildcard the parser does i += 2, which
    // consumes the second '?' as well, so "4A ?? 60" is one wildcard + hex pair
    // (len 3, not 4). Faithful as coded — see the review note in the README.
    auto p3 = PatternToBytes("4A ?? 60");
    CHECK(p3.Length == 3);
    CHECK(p3.Bytes[0] == '\x4A');
    CHECK(p3.Bytes[1] == '?');
    CHECK(p3.Bytes[2] == '\x60');

    // one-nibble + '?': HexToByte('?') == 0xFF folds into the low nibble
    auto p4 = PatternToBytes("0?");
    CHECK(p4.Length == 1);
    CHECK(static_cast<unsigned char>(p4.Bytes[0]) == 0xFF);

    // mixed-case nibbles
    auto p5 = PatternToBytes("4a fF");
    CHECK(p5.Length == 2);
    CHECK(p5.Bytes[0] == '\x4A' && p5.Bytes[1] == '\xFF');

    // empty signature: length 0, terminator only
    auto p6 = PatternToBytes("");
    CHECK(p6.Length == 0 && p6.Bytes[0] == '\0');

    // round-trip through the Pattern<N> EncodeBytes/Decode in Scan.cpp
    auto e = EncodeBytes(p1);
    auto d = Decode(e);
    CHECK(d.Length == p1.Length);
    CHECK(memcmp(d.data(), p1.data(), p1.Length) == 0);
}

static void TestSignatureScan()
{
    // SignatureScan's runtime contract: the caller passes the DECODED signature
    // bytes (PatternToBytes output), not the textual pattern — the scan path
    // treats each character as a byte of the compared pattern.
    auto Parse = [](auto&& text) {
        auto decoded = PatternToBytes(text);
        return decoded;
    };

    // synthetic buffer with two matches of the same signature
    const unsigned char buf[] = {0x10, 0xA9, 0x4A, 0x11, 0x22, 0x60,
                                 0x55, 0x4A, 0x11, 0x22, 0x60};
    const void* Start = buf;
    const void* End = buf + sizeof(buf);

    {
        const auto sig = Parse("4A 11 22 60");
        const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
        CHECK(hit == reinterpret_cast<const void*>(buf + 2));  // leftmost, not 7
    }
    {
        const auto sig = Parse("10 A9 4A 11");
        const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
        CHECK(hit == Start);
    }
    {
        const auto sig = Parse("?? 11 ?? 60");
        const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
        CHECK(hit == buf + 2);
    }
    {
        // all-wildcard matches the very first position (First == size)
        const auto sig = Parse("?? ?? ?? ??");
        CHECK(sig.Length == 4);
        const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
        CHECK(hit == Start);
    }
    {
        // first-byte reject: the anchor byte appears at 6 exactly
        const auto sig = Parse("55 4A 11 22");
        const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
        CHECK(hit == buf + 6);
    }
    {
        const auto sig = Parse("77 88 99 AA");
        CHECK(SignatureScan(Start, End, sig.data(), sig.Length) == nullptr);
    }
    {
        // range shorter than the signature (the wrap guard)
        const auto sig = Parse("4A 11 22 60");
        CHECK(SignatureScan(Start, buf + 3, sig.data(), sig.Length) == nullptr);
    }
    {
        const auto sig = Parse("4A 11 22 60");
        CHECK(SignatureScan(Start, End, "", 0) == nullptr);       // empty -> reject
    }
    {
        const auto sig = Parse("4A 11 22 60");
        CHECK(SignatureScan(nullptr, End, sig.data(), sig.Length) == nullptr);
    }

    // boundary cases
    {
        // exact-size range (End == Start + size) still matches at Start
        const auto sig = Parse("10 A9 4A 11");
        CHECK(SignatureScan(Start, buf + sig.Length, sig.data(), sig.Length) == Start);
    }
    {
        // reversed range: End < Start. The product has no explicit reject; the
        // loop simply never executes (documented here so a future guard change
        // is visible).
        const auto sig = Parse("4A 11 22 60");
        CHECK(SignatureScan(buf + 3, buf, sig.data(), sig.Length) == nullptr);
    }
    {
        const auto sig = Parse("4A 11 22 60");
        CHECK(SignatureScan(Start, nullptr, sig.data(), sig.Length) == nullptr);
        CHECK(SignatureScan(Start, End, nullptr, 4) == nullptr);
    }
}

static void TestSignatureLiteral3FQuirk()
{
    // DOCUMENTED QUIRK: the wildcard sentinel is the byte value '?' (0x3F), so
    // a signature that wants to match a *literal* 0x3F byte is treated as a
    // wildcard by Matches() (Scan.cpp:106-111). No current Strings.h signature
    // contains 0x3F; this test pins the behavior for future pattern authors.
    const unsigned char buf[] = {0x00, 0x3F};
    const void* Start = buf;
    const void* End = buf + sizeof(buf);

    auto sig = PatternToBytes("3F 3F");
    CHECK(sig.Length == 2);
    CHECK(static_cast<unsigned char>(sig.Bytes[0]) == 0x3F);
    // the literal 3F behaves as a wildcard: it matches the zero at offset 0
    const auto hit = SignatureScan(Start, End, sig.data(), sig.Length);
    CHECK(hit == Start);
}

static void TestStringHelpers()
{
    CHECK(StringLength("ntoskrnl") == 8);
    CHECK(StringLength("") == 0);
    CHECK(StringEquals("ntoskrnl.exe", "ntoskrnl.exe"));
    CHECK(!StringEquals("ntoskrnl.exe", "Ntoskrnl.exe"));   // byte-sensitive
    CHECK(StringEquals("", ""));
    CHECK(!StringEquals("abc", "ab"));                      // prefix, shorter RHS
    CHECK(!StringEquals("ab", "abc"));                      // prefix, longer RHS

    CHECK(BytesEqual("abc", "abc", 3));
    CHECK(!BytesEqual("abc", "abd", 3));
    CHECK(BytesEqual(nullptr, nullptr, 0));
    CHECK(BytesEqual("abc", "abd", 0));                     // size 0 always equal

    CHECK(WideStringLength(L"Ci.dll") == 6);
    CHECK(WideStringLength(L"") == 0);
    CHECK(WideStringEquals(L"Ci.dll", L"Ci.dll"));
    CHECK(!WideStringEquals(L"Ci.dll", L"ci.dll"));         // byte compare, no fold
    CHECK(WideStringEquals(L"", L""));
    CHECK(!WideStringEquals(L"Ci.dll", L"Ci"));             // prefix, shorter RHS
    CHECK(!WideStringEquals(L"Ci", L"Ci.dll"));             // prefix, longer RHS
}

// ===========================================================================
// 3. Scan.cpp exports + Locate.cpp (ScanModuleImage / ResolveRipRelative)
// ===========================================================================

// A minimal PE32+ image in MAPPED layout (RVA == buffer offset), which is what
// FindFuncExports/SectionScan/ScanModuleImage expect: export directory at RVA
// 0x1000 (Foo -> RVA 0x1100, Bar -> RVA 0x1200), PAGE section at 0x1800.
// Signature bytes live at PAGE RVA 0x1810 and .text RVA 0x11F0.
static std::vector<uint8_t> BuildDriverPe()
{
    std::vector<uint8_t> f(0x2000, 0);

    auto* dos = reinterpret_cast<_IMAGE_DOS_HEADER*>(f.data());
    dos->e_magic = 0x5A4D;                     // IMAGE_DOS_SIGNATURE
    dos->e_lfanew = 0x40;

    auto* nt = reinterpret_cast<_IMAGE_NT_HEADERS64*>(f.data() + 0x40);
    nt->Signature = 0x00004550;                // IMAGE_NT_SIGNATURE
    nt->FileHeader.Machine = 0x8664;
    nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(_IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = 0x20B;          // PE32+
    nt->OptionalHeader.ImageBase = 0x140000000ull;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.SizeOfHeaders = 0x400;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.DataDirectory[0] = {0x1000, 0x100};   // export directory

    auto* sec = reinterpret_cast<_IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&nt->OptionalHeader) + sizeof(_IMAGE_OPTIONAL_HEADER64));
    memcpy(sec[0].Name, ".text", 6);
    sec[0].Misc.VirtualSize = 0x200;
    sec[0].VirtualAddress = 0x1000;
    sec[0].SizeOfRawData = 0x200;
    sec[0].PointerToRawData = 0x1000;          // mapped layout
    sec[0].Characteristics = 0x60000020;       // code | execute | read

    memcpy(sec[1].Name, "PAGE", 5);
    sec[1].Misc.VirtualSize = 0x100;
    sec[1].VirtualAddress = 0x1800;
    sec[1].SizeOfRawData = 0x100;
    sec[1].PointerToRawData = 0x1800;          // mapped layout
    sec[1].Characteristics = 0x40000040;       // initialized data | read

    auto* exp = reinterpret_cast<_IMAGE_EXPORT_DIRECTORY*>(f.data() + 0x1000);
    exp->NumberOfFunctions = 2;
    exp->NumberOfNames = 2;
    exp->AddressOfFunctions = 0x1040;
    exp->AddressOfNames = 0x1060;
    exp->AddressOfNameOrdinals = 0x1080;

    auto* funcs = reinterpret_cast<ULONG*>(f.data() + 0x1040);
    funcs[0] = 0x1100;
    funcs[1] = 0x1200;
    auto* names = reinterpret_cast<ULONG*>(f.data() + 0x1060);
    names[0] = 0x10A0;
    names[1] = 0x10A8;
    auto* ords = reinterpret_cast<USHORT*>(f.data() + 0x1080);
    ords[0] = 0;
    ords[1] = 1;
    memcpy(f.data() + 0x10A0, "Foo", 4);
    memcpy(f.data() + 0x10A8, "Bar", 4);

    const uint8_t pageSig[] = {0xDE, 0xAD, 0xBE, 0xEF};
    memcpy(f.data() + 0x1810, pageSig, 4);     // PAGE RVA 0x1810
    const uint8_t textSig[] = {0xCA, 0xFE, 0xBA, 0xBE};
    memcpy(f.data() + 0x11F0, textSig, 4);     // .text RVA 0x11F0

    return f;
}

static void TestFindFuncExports()
{
    auto image = BuildDriverPe();
    const uintptr_t Base = reinterpret_cast<uintptr_t>(image.data());

    CHECK(AddrOf(FindFuncExports(image.data(), "Foo")) == Base + 0x1100);
    CHECK(AddrOf(FindFuncExports(image.data(), "Bar")) == Base + 0x1200);
    CHECK(FindFuncExports(image.data(), "Baz") == nullptr);

    const char* wanted[3] = {"Foo", "Bar", "Baz"};
    address results[3] = {};
    FindFuncExportsBatch(image.data(), wanted, results, 3);
    CHECK(AddrOf(results[0]) == Base + 0x1100);
    CHECK(AddrOf(results[1]) == Base + 0x1200);
    CHECK(results[2] == nullptr);

    // no export directory -> null results
    auto noExport = BuildDriverPe();
    reinterpret_cast<_IMAGE_NT_HEADERS64*>(noExport.data() + 0x40)
        ->OptionalHeader.DataDirectory[0] = {0, 0};
    CHECK(FindFuncExports(noExport.data(), "Foo") == nullptr);
    address none[1] = {};
    FindFuncExportsBatch(noExport.data(), wanted, none, 1);
    CHECK(none[0] == nullptr);
}

static void TestSectionScanAndModuleScan()
{
    auto image = BuildDriverPe();
    const uintptr_t Base = reinterpret_cast<uintptr_t>(image.data());

    auto pageSig = PatternToBytes("DE AD BE EF");
    CHECK(AddrOf(SectionScan(image.data(), "PAGE", pageSig.data(), pageSig.Length))
          == Base + 0x1810);
    CHECK(AddrOf(ScanModuleImage(image.data(), pageSig)) == Base + 0x1810);

    // signature only in .text: PAGE misses, .text fallback hits
    auto textSig = PatternToBytes("CA FE BA BE");
    CHECK(AddrOf(ScanModuleImage(image.data(), textSig)) == Base + 0x11F0);

    // missing section -> nullptr; null base -> nullptr
    auto missing = PatternToBytes("11 22 33 44");
    CHECK(SectionScan(image.data(), "NOPE", missing.data(), missing.Length) == nullptr);
    CHECK(ScanModuleImage(nullptr, pageSig) == nullptr);

    // VirtualSize == 0 gives an empty scan range, so even a present section
    // cannot match (SectionScan uses Misc.VirtualSize, not SizeOfRawData)
    auto emptySection = BuildDriverPe();
    reinterpret_cast<_IMAGE_NT_HEADERS64*>(emptySection.data() + 0x40)
        ->OptionalHeader.DataDirectory[0] = {0x1000, 0x100};
    auto* sec = reinterpret_cast<_IMAGE_SECTION_HEADER*>(
        reinterpret_cast<uint8_t*>(&reinterpret_cast<_IMAGE_NT_HEADERS64*>(
            emptySection.data() + 0x40)->OptionalHeader) + sizeof(_IMAGE_OPTIONAL_HEADER64));
    sec[1].Misc.VirtualSize = 0;
    CHECK(SectionScan(emptySection.data(), "PAGE", pageSig.data(), pageSig.Length) == nullptr);
}

static void TestResolveRipRelative()
{
    uint8_t instr[16] = {};
    int32_t disp = -0x10;
    memcpy(instr + 3, &disp, sizeof(disp));
    CHECK(AddrOf(ResolveRipRelative(instr, 3, 7))
          == reinterpret_cast<uintptr_t>(instr) + 7 - 0x10);

    int32_t positive = 0x40;
    memcpy(instr + 3, &positive, sizeof(positive));
    CHECK(AddrOf(ResolveRipRelative(instr, 3, 6))
          == reinterpret_cast<uintptr_t>(instr) + 6 + 0x40);
}

template<size_t N>
static void CheckStringsPattern(const Pattern<N>& P)
{
    CHECK(P.Length > 0 && P.Length <= 64);
    // A literal 0x3F byte would be treated as a wildcard by Matches(); no
    // current signature may contain one.
    bool literal3F = false;
    for (size_t i = 0; i < P.Length; ++i)
        if (static_cast<unsigned char>(P.Bytes[i]) == 0x3F) literal3F = true;
    CHECK(!literal3F);
}

static void TestStringsHeader()
{
    // Decoded names must equal the plaintext the driver searches for.
    CHECK(strcmp(Decode(NtoskrnlName).data(), "ntoskrnl.exe") == 0);
    CHECK(strcmp(Decode(PageSectionName).data(), "PAGE") == 0);
    CHECK(strcmp(Decode(TextSectionName).data(), ".text") == 0);
    CHECK(wcscmp(Decode(CiDllName).data(), L"ci.dll") == 0);
    CHECK(wcscmp(Decode(WdFilterName).data(), L"WdFilter.sys") == 0);

    // Pinned lengths: a wrong token count changes what the scanner matches.
    CHECK(PiDDBCacheListSignature.Length == 17);
    CHECK(PiDDBCacheTableSignature.Length == 15);
    CHECK(MmUnloadedDriversSignature.Length == 10);
    CHECK(MmLastUnloadedDriverSignature.Length == 9);
    CHECK(PteBaseSignature.Length == 13);
    CHECK(PfnPteAddressSignature.Length == 18);

    CheckStringsPattern(PiDDBCacheListSignature);
    CheckStringsPattern(PiDDBCacheTableSignature);
    CheckStringsPattern(PiDDBLockSignature);
    CheckStringsPattern(MmUnloadedDriversSignature);
    CheckStringsPattern(MmLastUnloadedDriverSignature);
    CheckStringsPattern(KernelHashBucketListSignature21H1);
    CheckStringsPattern(KernelHashBucketListSignature22H2);
    CheckStringsPattern(WdFilterRuntimeDriversListSignature);
    CheckStringsPattern(WdFilterRuntimeDriversCountSignature);
    CheckStringsPattern(WdFilterFreeDriverInfoSignature);
    CheckStringsPattern(WdFilterFreeDriverInfoSignatureAlt);
    CheckStringsPattern(PteBaseSignature);
    CheckStringsPattern(PfnPteAddressSignature);
}

// ===========================================================================
// 4. Lib/pure.h + Common/Command.h — kernel-side pure helpers and the
//    shared-memory channel ABI
// ===========================================================================

static void TestWideEqualsIgnoreCase()
{
    CHECK(WideEqualsIgnoreCase(L"Ci.dll", L"ci.DLL", 6));
    CHECK(WideEqualsIgnoreCase(L"ci.dll", L"Ci.dll", 6));
    CHECK(WideEqualsIgnoreCase(L"WdFilter.sys", L"wdfilter.SYS", 12));

    // B must end exactly at Count: extra characters mean no match.
    CHECK(!WideEqualsIgnoreCase(L"Ci.dll", L"ci.dllx", 6));
    CHECK(!WideEqualsIgnoreCase(L"Ci", L"Ci.dll", 2));
    // A ending early is a mismatch too.
    CHECK(!WideEqualsIgnoreCase(L"Ci.dll", L"Ci", 6));

    CHECK(WideEqualsIgnoreCase(L"", L"", 0));
    CHECK(!WideEqualsIgnoreCase(L"", L"x", 0));
}

static void TestIsObjectKernelPointer()
{
    CHECK(IsObjectKernelPointer(0xFFFF800000000000ull));
    CHECK(IsObjectKernelPointer(0xFFFFFFFFFFFFFFFFull));
    CHECK(!IsObjectKernelPointer(0xFFFF7FFFFFFFFFFFull));
    CHECK(!IsObjectKernelPointer(0x00007FFFFFFF0000ull));
    CHECK(!IsObjectKernelPointer(0));
}

static void TestChannelHeaderAbi()
{
    CHECK(sizeof(ChannelHeader) == 0x30);
    CHECK(offsetof(ChannelHeader, Magic) == 0x00);
    CHECK(offsetof(ChannelHeader, Sequence) == 0x04);
    CHECK(offsetof(ChannelHeader, Ack) == 0x08);
    CHECK(offsetof(ChannelHeader, Status) == 0x0C);
    CHECK(offsetof(ChannelHeader, Op) == 0x10);
    CHECK(offsetof(ChannelHeader, TargetPid) == 0x14);
    CHECK(offsetof(ChannelHeader, Size) == 0x18);
    CHECK(offsetof(ChannelHeader, Reserved) == 0x1C);
    CHECK(offsetof(ChannelHeader, RemoteAddress) == 0x20);
    CHECK(offsetof(ChannelHeader, Heartbeat) == 0x28);

    CHECK(ChannelMagic == 0x31494345);          // "ECI1"
    CHECK(ChannelBytes == 0x100000);
    CHECK(ChannelDataAt == 0x40);
    CHECK(ChannelDataMax == 0xFFFC0);
    CHECK(static_cast<uint32_t>(op_ping) == 1);
    CHECK(static_cast<uint32_t>(op_read) == 2);
    CHECK(static_cast<uint32_t>(op_write) == 3);
}

// ===========================================================================
// harness
// ===========================================================================

static void RunDriverUnitTests()
{
    TestEncodeNameContract();
    TestEncodedNamesCrossDecode();
    TestXorSeedSymmetry();
    TestEncodeBytesRoundTrip();

    TestHexToByte();
    TestPatternToBytes();
    TestSignatureScan();
    TestSignatureLiteral3FQuirk();
    TestStringHelpers();
    TestFindFuncExports();
    TestSectionScanAndModuleScan();
    TestResolveRipRelative();
    TestStringsHeader();

    TestWideEqualsIgnoreCase();
    TestIsObjectKernelPointer();
    TestChannelHeaderAbi();
}

int main()
{
    RunDriverUnitTests();
    std::printf("\n==== kf_driver_tests: %u passed, %u failed ====\n",
                g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
