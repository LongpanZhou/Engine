// ---------------------------------------------------------------------------
// Engine-ci/tests/host/mapload_tests.cpp
//
// Host-side unit tests for mapload's pure logic (no provider/KernelForge/SCM
// traffic happens here):
//   * mapper/map.cpp    — MapImage's helpers exercised as fragments:
//                         RangeInImage, ApplyRelocs (+reject paths),
//                         ResolveImports (+reject paths),
//                         StripImportMetadata; a minimal PE image is built in
//                         the test so the layouts are under our control.
//   * controller/config.cpp — the mapload.json reader: Parser::ParseObject
//                         for full/defaults/unknown-keys/number-formats/
//                         malformed cases and LoadConfig's temp-file path.
//
// Both fragments are static/anonymous inside their translation units, so the
// fragments themselves are included. The control layer (IsHvciAllowed, Log,
// WorkspaceRoot, EnablePrivilege, ShutdownProvider, LogSetQuiet) and the
// KernelForge foreign-memory layer (KfGetKernelProcAddress, KfHeapAlloc,
// KfMemCopy, ...) are stubbed — the unit tests never touch real kernel
// surfaces.
//
// Built and run by scripts/run-unit-tests.ps1 (Debug gate); never ships.
// No external framework: micro harness of CHECK() counters.
// ---------------------------------------------------------------------------

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdarg.h>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "../../../mapload/controller/controller.h"
#include "../../../KernelForge/include/kforge_library.h"
#include "../../../KernelForge/include/kforge_driver.h"
#include "../../../mapload/controller/config.h"
#include "../../../mapload/controller/pure.h"

// --- Host stubs ----------------------------------------------------------
// map.cpp/config.cpp call Log() directly; the tests never exercise the
// provider/KernelForge layers, so stub every external they touch.
namespace mapload {
    static bool IsHvciAllowed() { return true; }
    static void ShutdownProvider() {}
    static void LogSetQuiet(bool) {}
    // Forwards to stdout with a [stub-Log] tag so the product's own branch
    // diagnostics surface in the test output (this is how ResolveImports
    // rejects were localized in the mapload unit tests).
    static void Log(const char* fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        std::printf("[stub-Log] ");
        std::vprintf(fmt, args);
        std::printf("\n");
        va_end(args);
    }
    static bool EnablePrivilege(const char*) { return true; }
    // Configurable workspace root for LoadConfig("") tests.
static char g_TestWorkspaceRoot[MAX_PATH] = {};

static void WorkspaceRoot(char* out, size_t outlen)
    {
        if (!out || !outlen) return;
        strncpy_s(out, outlen, g_TestWorkspaceRoot, _TRUNCATE);
    }
} // namespace mapload

// Host stubs for the KernelForge foreign-memory layer. MapImage requires a
// kernel-range base and touches it only through KfMemSet/KfMemCopy/
// DriverMemRead/DriverMemWrite, so the stubs emulate a small kernel heap:
// addresses live in the 0xFFFFF800... range and translate to host buffers.
// KfGetKernelProcAddress records the last name and returns a deterministic
// address, so ResolveImports can be checked exactly (address AND name).
static char g_LastResolvedName[128] = {};

struct FakeKernelHeap
{
    struct Block
    {
        uint64_t Base;
        std::vector<uint8_t> Data;
    };
    std::vector<Block> Blocks;
    uint64_t Next = 0xFFFFF80000000123ull;   // deliberately not page-aligned

    uint64_t Alloc(size_t Size)
    {
        const uint64_t Base = Next;
        Blocks.push_back({Base, std::vector<uint8_t>(Size, 0xCD)});
        Next += (Size + 0xFFF) & ~static_cast<size_t>(0xFFF);
        return Base;
    }

    void Free(uint64_t Base)
    {
        for (auto it = Blocks.begin(); it != Blocks.end(); ++it)
            if (it->Base == Base) { Blocks.erase(it); return; }
    }

    uint8_t* Translate(uint64_t Addr, size_t Size)
    {
        for (auto& B : Blocks)
            if (Addr >= B.Base && Addr - B.Base + Size <= B.Data.size())
                return B.Data.data() + (Addr - B.Base);
        return nullptr;
    }
};
static FakeKernelHeap g_Heap;

extern "C" {
    static PVOID KfGetKernelProcAddress(char* name)
    {
        std::memset(g_LastResolvedName, 0, sizeof(g_LastResolvedName));
        std::strncpy(g_LastResolvedName, name, sizeof(g_LastResolvedName) - 1);
        static const uint64_t fake = 0xFFFFF8012C600000ull;
        return reinterpret_cast<PVOID>(fake + strlen(name));
    }
    static PVOID KfHeapAlloc(SIZE_T Size)
    {
        return reinterpret_cast<PVOID>(g_Heap.Alloc(Size));
    }
    static PVOID KfHeapAllocData(SIZE_T Size, PVOID Data)
    {
        const uint64_t Base = g_Heap.Alloc(Size);
        if (Data && Size)
            std::memcpy(g_Heap.Translate(Base, Size), Data, Size);
        return reinterpret_cast<PVOID>(Base);
    }
    static void KfHeapFree(PVOID Addr)
    {
        g_Heap.Free(reinterpret_cast<uint64_t>(Addr));
    }
    static PVOID KfMemCopy(PVOID Dst, PVOID Src, SIZE_T Size)
    {
        auto* d = g_Heap.Translate(reinterpret_cast<uint64_t>(Dst), Size);
        if (!d) return nullptr;
        std::memcpy(d, Src, Size);
        return Dst;
    }
    static PVOID KfMemSet(PVOID Dst, int Val, SIZE_T Size)
    {
        auto* d = g_Heap.Translate(reinterpret_cast<uint64_t>(Dst), Size);
        if (!d) return nullptr;
        std::memset(d, Val, Size);
        return Dst;
    }
    static PVOID KfAllocIndependentPages(SIZE_T Size)
    {
        return reinterpret_cast<PVOID>(g_Heap.Alloc(Size));
    }
    static BOOL KfFreeIndependentPages(PVOID Addr, SIZE_T)
    {
        g_Heap.Free(reinterpret_cast<uint64_t>(Addr));
        return TRUE;
    }
    static BOOL DriverInit(void) { return FALSE; }
    static BOOL DriverUninit(void) { return FALSE; }
    static BOOL DriverMemRead(PVOID Addr, PVOID Data, DWORD_PTR Size)
    {
        auto* s = g_Heap.Translate(reinterpret_cast<uint64_t>(Addr), Size);
        if (!s) return FALSE;
        std::memcpy(Data, s, Size);
        return TRUE;
    }
    static BOOL DriverMemWrite(PVOID Addr, PVOID Data, DWORD_PTR Size)
    {
        auto* d = g_Heap.Translate(reinterpret_cast<uint64_t>(Addr), Size);
        if (!d) return FALSE;
        std::memcpy(d, Data, Size);
        return TRUE;
    }
}

// Deliberately no `_strtoui64` remap: the MSVC C++ runtime provides it natively
// (and mapload already compiles cleanly there).

#include "../../../mapload/mapper/map.cpp"
#include "../../../mapload/controller/config.cpp"

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

// ===========================================================================
// 1. mapper/map.cpp — range guard + relocations
// ===========================================================================

// Minimal 64-bit PE: 64-byte DOS header at 0, NT headers at 0x40, one
// ".text" section header; SizeOfImage 0x2000. DataDirectories returned via
// the two input RVA/Size pairs.
static std::vector<uint8_t> BuildMiniPe(DWORD RelocRva, DWORD RelocSize,
                                        DWORD ImportRva, DWORD ImportSize)
{
    std::vector<uint8_t> image(0x2000, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] =
        {RelocRva, RelocSize};
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        {ImportRva, ImportSize};

    auto* sec = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        image.data() + 0x40 + sizeof(IMAGE_NT_HEADERS64));
    memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x1000;

    return image;
}

static void TestRangeInImage()
{
    CHECK(mapload::mapper::RangeInImage(0, 0, 0x1000));
    CHECK(mapload::mapper::RangeInImage(0xFFF, 1, 0x1000));
    CHECK(!mapload::mapper::RangeInImage(0x1000, 1, 0x1000));   // start past end
    CHECK(!mapload::mapper::RangeInImage(1, 0x1000, 0x1000));   // would overflow
    CHECK(mapload::mapper::RangeInImage(5, 0, 0x1000));         // zero length
    // documented edge: offset == image size with a zero-length range is
    // *in-bounds* by the product guard (offset <= size && len <= size - offset)
    CHECK(mapload::mapper::RangeInImage(0x2000, 0, 0x2000));
    CHECK(!mapload::mapper::RangeInImage(0x2001, 0, 0x2000));   // past the end
    CHECK(!mapload::mapper::RangeInImage(0, 0x1001, 0x1000));   // length > size
    CHECK(mapload::mapper::RangeInImage(0x1000, 0, 0x1000));    // zero at the edge
    CHECK(!mapload::mapper::RangeInImage(0x1000, 1, 0x1000));
}

static void TestApplyRelocs()
{
    // valid DIR64 + ABSOLUTE block: the DIR64 target is patched by deltaBase,
    // the ABSOLUTE entry is skipped, and the probe carries the first patch.
    std::vector<uint8_t> image = BuildMiniPe(0x1800, 16, 0, 0);
    const uint64_t deltaBase = 0x4000'0000ull;

    auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1800);
    rel->VirtualAddress = 0x1000;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 2 * sizeof(WORD);
    auto* words = reinterpret_cast<WORD*>(image.data() + 0x1800
                                          + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x010);
    words[1] = static_cast<WORD>((IMAGE_REL_BASED_ABSOLUTE << 12) | 0x000);

    const uint64_t pre = 0x1400000000001234ull;
    memcpy(image.data() + 0x1010, &pre, 8);

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 16};

    mapload::mapper::RelocProbe probe{};
    CHECK(mapload::mapper::ApplyRelocs(image.data(), 0x2000, deltaBase, &probe));

    uint64_t after = 0;
    memcpy(&after, image.data() + 0x1010, 8);
    CHECK(after == pre + deltaBase);
    CHECK(probe.valid);
    CHECK(probe.rva == 0x1010);
    CHECK(probe.expected == after);

    // second application with the probe pre-filled must not overwrite the probe
    mapload::mapper::RelocProbe probe2{true, 0x99, 0x98};
    CHECK(mapload::mapper::ApplyRelocs(image.data(), 0x2000, deltaBase, &probe2));
    CHECK(probe2.rva == 0x99 && probe2.expected == 0x98);
}

static void TestApplyRelocsRejects()
{
    auto image = BuildMiniPe(0, 16, 0, 0);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0, 16};
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    // directory range outside the image: {0x1FF8, 16} ends at 0x2008 > 0x2000,
    // rejected by the RangeInImage guard before any block is read
    image = BuildMiniPe(0, 0, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1FF8, 16};
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    // malformed block: a zero-filled block has SizeOfBlock == 0, rejected by
    // the per-block sanity check
    image = BuildMiniPe(0x1F00, 16, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1F00, 16};
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    // block claiming more bytes than the directory grants -> malformed
    image = BuildMiniPe(0x1800, 16, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 16};
    auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1800);
    rel->VirtualAddress = 0x1000;
    rel->SizeOfBlock = 0x1000;                    // larger than dir size
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    // unsupported relocation type -> reject (type 6 = IMAGE_REL_BASED_SECTION;
    // some SDK headers omit it, so aim for a type that never ships on x64)
    image = BuildMiniPe(0x1800, 16, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 16};
    rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1800);
    rel->VirtualAddress = 0x1000;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 1 * sizeof(WORD);
    auto* words = reinterpret_cast<WORD*>(image.data() + 0x1800
                                          + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((0x6 << 12) | 0x010);
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    // DIR64 *target* outside the image: the target is the block's VirtualAddress
    // plus the 12-bit offset, so the block VA itself must sit at the top of the
    // image (target = 0x1F00 + 0x0F9 = 0x1FF9; 8 bytes needed, 7 remain).
    image = BuildMiniPe(0x1F00, 16, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1F00, 16};
    rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1F00);
    rel->VirtualAddress = 0x1F00;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 1 * sizeof(WORD);
    words = reinterpret_cast<WORD*>(image.data() + 0x1F00 + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x0F9);
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));
}

static void TestApplyRelocsEmptyDirectory()
{
    // A nonzero RVA with Size 0 short-circuits to "no relocations" (true), and
    // a fully empty directory {0,0} is the normal no-reloc case.
    auto image = BuildMiniPe(0x1800, 0, 0, 0);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 0};
    CHECK(mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));

    image = BuildMiniPe(0, 0, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0, 0};
    CHECK(mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));
}

static void TestApplyRelocsHighlow()
{
    // HIGHLOW (type 3) is unexpected on x64 but still applied: the low 32 bits
    // get the delta and the rest of the image is untouched.
    auto image = BuildMiniPe(0x1800, 16, 0, 0);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 16};
    auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1800);
    rel->VirtualAddress = 0x1000;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 1 * sizeof(WORD);
    auto* words = reinterpret_cast<WORD*>(image.data() + 0x1800 + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x020);

    *reinterpret_cast<uint32_t*>(image.data() + 0x1020) = 0x11223344;
    CHECK(mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));
    CHECK(*reinterpret_cast<uint32_t*>(image.data() + 0x1020) == 0x11224344u);

    // HIGHLOW target outside the image: block VA 0x1FFE + 4 bytes > 0x2000
    image = BuildMiniPe(0x1800, 16, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x1800, 16};
    rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(image.data() + 0x1800);
    rel->VirtualAddress = 0x1FFE;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 1 * sizeof(WORD);
    words = reinterpret_cast<WORD*>(image.data() + 0x1800 + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x000);
    CHECK(!mapload::mapper::ApplyRelocs(image.data(), 0x2000, 0x1000, nullptr));
}

// ===========================================================================
// 2. mapper/map.cpp — import resolution
// ===========================================================================

// Import descriptor for ntoskrnl.exe at dirRva with one by-name entry whose
// module name/by-name string live inside the image. Also publishes the import
// data-directory entry (VA + 2 descriptors), which the loader contract needs
// for `dir.Size >= sizeof(IMAGE_IMPORT_DESCRIPTOR)` before a single import can
// be walked.
static void AddNtImport(std::vector<uint8_t>& image, uint32_t dirRva)
{
    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + dirRva);
    const char* name = "ntoskrnl.exe";
    memcpy(image.data() + dirRva + 0x40, name, strlen(name) + 1);
    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image.data() + dirRva + 0x60);
    byName->Hint = 1;
    const char* fname = "PsLookupProcessByProcessId";
    memcpy(byName->Name, fname, strlen(fname) + 1);

    imp->Name = dirRva + 0x40;
    imp->OriginalFirstThunk = dirRva + 0x90;
    imp->FirstThunk = dirRva + 0x80;

    auto* orig = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + dirRva + 0x90);
    orig->u1.AddressOfData = dirRva + 0x60;
    (orig + 1)->u1.AddressOfData = 0;                       // terminator

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        {dirRva, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2};
}

// ===========================================================================
// 2. mapper/map.cpp — import resolution
// ===========================================================================

static void TestResolveImportsOk()
{
    std::vector<uint8_t> image = BuildMiniPe(0, 0, 0, 0);
    AddNtImport(image, 0x1700);            // publishes dir = {0x1700, 0x28}

    CHECK(mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));

    // exact fake address = 0xFFFFF8012C600000 + strlen("PsLookupProcessByProcessId")
    // (26) -> a wrong or empty name passed to the resolver cannot pass this
    CHECK(strcmp(g_LastResolvedName, "PsLookupProcessByProcessId") == 0);
    auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1700 + 0x80);
    CHECK(thunk->u1.Function == 0xFFFFF8012C60001Aull);

    // the ILT (OriginalFirstThunk) is not modified by resolution; the
    // terminator slot stays zero
    auto* orig = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1700 + 0x90);
    CHECK(orig[0].u1.AddressOfData == 0x1760u);
    CHECK(orig[1].u1.AddressOfData == 0);
}

static void TestResolveImportsRejects()
{
    // descriptor chain whose module name slot holds zeros: the empty name fails
    // the ntoskrnl-only _stricmp check (there is no explicit blank-name test in
    // the product; the empty string simply does not equal "ntoskrnl.exe")
    auto image = BuildMiniPe(0, 0, 0, 0);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        {0x1700, sizeof(IMAGE_IMPORT_DESCRIPTOR)};

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x1700);
    imp->Name = 0x1740;
    imp->OriginalFirstThunk = 0x1790;
    imp->FirstThunk = 0x1750;
    CHECK(!mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));

    // non-ntoskrnl import -> reject (the mapload contract is ntoskrnl-only)
    image = BuildMiniPe(0, 0, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        {0x1700, sizeof(IMAGE_IMPORT_DESCRIPTOR)};
    imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x1700);
    memcpy(image.data() + 0x1740, "user32.dll", 10);
    imp->Name = 0x1740;
    imp->OriginalFirstThunk = 0x1790;
    imp->FirstThunk = 0x1750;
    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image.data() + 0x1790 + 0x20);
    byName->Hint = 1;
    memcpy(byName->Name, "MessageBoxW", 11);
    auto* orig = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1790);
    orig[0].u1.AddressOfData = static_cast<uint64_t>(0x1790) + 0x20;   // the byName rva
    CHECK(!mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));

    // no-import image resolves trivially ("imports: none declared")
    image = BuildMiniPe(0, 0, 0, 0);
    nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0, 0};
    CHECK(mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));
}

static void TestResolveImportsRejectsExpanded()
{
    const DWORD size = 0x2000;
    auto ntOf = [](std::vector<uint8_t>& image) {
        return reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    };
    auto impOf = [](std::vector<uint8_t>& image) {
        return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x1700);
    };
    auto iltOf = [](std::vector<uint8_t>& image) {
        return reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1700 + 0x90);
    };

    // directory too small for one descriptor
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        ntOf(image)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
            {0x1700, 8};
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // module-name RVA outside the image (NameInImage rejects at >= imageSize)
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        AddNtImport(image, 0x1700);
        impOf(image)->Name = 0x2000;
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // ordinal import is not supported
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        AddNtImport(image, 0x1700);
        iltOf(image)->u1.Ordinal = IMAGE_ORDINAL_FLAG64 | 5;
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // by-name RVA outside the image
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        AddNtImport(image, 0x1700);
        iltOf(image)->u1.AddressOfData = 0x1FFF;
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // FirstThunk == 0 with a valid name/ILT is invalid
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        AddNtImport(image, 0x1700);
        impOf(image)->FirstThunk = 0;
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // descriptor table outside the image
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        ntOf(image)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
            {0x1FF0, 0x20};
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // 256 valid descriptors with no terminator -> fail closed instead of looping
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        auto* nt = ntOf(image);
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x600, 0x1400};
        memcpy(image.data() + 0x1A00, "ntoskrnl.exe", 13);
        auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image.data() + 0x1A20);
        byName->Hint = 1;
        memcpy(byName->Name, "PsLookupProcessByProcessId", 27);
        auto* thunks = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1A40);
        thunks[0].u1.AddressOfData = 0;                 // empty import list
        for (uint32_t i = 0; i < 256; ++i)
        {
            auto* d = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
                image.data() + 0x600 + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
            d->Name = 0x1A00;
            d->OriginalFirstThunk = 0x1A40;
            d->FirstThunk = 0x1A80;
        }
        CHECK(!mapload::mapper::ResolveImports(image.data(), size));
    }

    // module name is matched case-insensitively (_stricmp)
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        AddNtImport(image, 0x1700);
        memcpy(image.data() + 0x1740, "NTOSKRNL.EXE", 13);
        CHECK(mapload::mapper::ResolveImports(image.data(), size));
    }

    // documented asymmetry: RVA 0 with a nonzero Size is "none declared" here
    // (ApplyRelocs rejects the same shape), and {0,0} is the normal no-import case
    {
        auto image = BuildMiniPe(0, 0, 0, 0);
        ntOf(image)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
            {0, 0x28};
        CHECK(mapload::mapper::ResolveImports(image.data(), size));
        ntOf(image)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
            {0, 0};
        CHECK(mapload::mapper::ResolveImports(image.data(), size));
    }
}

static void TestStripImportMetadataOftZero()
{
    // OriginalFirstThunk == 0: ResolveImports uses FirstThunk as the name table
    // and overwrites it with the resolved pointer. StripImportMetadata only
    // walks OFT, so the hint/name string survives. The IAT still must survive
    // and the module name/descriptor are still wiped. This pins the documented
    // limitation (the by-name metadata is not stripped in this shape).
    auto image = BuildMiniPe(0, 0, 0, 0);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        {0x1700, sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2};

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x1700);
    memcpy(image.data() + 0x1740, "ntoskrnl.exe", 13);
    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(image.data() + 0x1760);
    byName->Hint = 1;
    memcpy(byName->Name, "PsLookupProcessByProcessId", 27);
    imp->Name = 0x1740;
    imp->FirstThunk = 0x1780;
    imp->OriginalFirstThunk = 0;

    auto* thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1780);
    thunk[0].u1.AddressOfData = 0x1760;
    thunk[1].u1.AddressOfData = 0;

    CHECK(mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));
    CHECK(thunk[0].u1.Function == 0xFFFFF8012C60001Aull);

    mapload::mapper::StripImportMetadata(image.data(), static_cast<DWORD>(image.size()));

    CHECK(thunk[0].u1.Function == 0xFFFFF8012C60001Aull);   // IAT survives
    CHECK(image[0x1740] == 0);                              // module name wiped
    // OFT == 0: the hint/name entry is NOT wiped (documented limitation)
    CHECK(strcmp(reinterpret_cast<const char*>(image.data() + 0x1762),
                 "PsLookupProcessByProcessId") == 0);
}

static void TestStripImportMetadata()
{
    std::vector<uint8_t> image = BuildMiniPe(0, 0, 0, 0);
    AddNtImport(image, 0x1700);
    CHECK(mapload::mapper::ResolveImports(image.data(), static_cast<DWORD>(image.size())));

    mapload::mapper::StripImportMetadata(image.data(), static_cast<DWORD>(image.size()));

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    CHECK(dir.VirtualAddress == 0 && dir.Size == 0);

    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + 0x1700);
    const uint8_t zero[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = {};
    CHECK(memcmp(imp, zero, sizeof(zero)) == 0);

    // The IAT must SURVIVE stripping (that is the whole point: the resolved
    // pointers are live), while the ILT, the hint/name entry and the module
    // name string are wiped.
    auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1700 + 0x80);
    CHECK(iat->u1.Function == 0xFFFFF8012C60001Aull);

    auto* ilt = reinterpret_cast<IMAGE_THUNK_DATA64*>(image.data() + 0x1700 + 0x90);
    CHECK(ilt[0].u1.AddressOfData == 0);
    CHECK(ilt[1].u1.AddressOfData == 0);

    // by-name entry: WORD hint + 26-byte name = 28 bytes zeroed
    bool byNameZero = true;
    for (uint32_t i = 0; i < 2 + 26; ++i)
        if (image[0x1700 + 0x60 + i] != 0) byNameZero = false;
    CHECK(byNameZero);

    // module name "ntoskrnl.exe" (12 bytes incl. NUL) fully zeroed
    bool nameZero = true;
    for (uint32_t i = 0; i < 12; ++i)
        if (image[0x1700 + 0x40 + i] != 0) nameZero = false;
    CHECK(nameZero);
}

// ===========================================================================
// 3. controller/config.cpp — mapload.json Parser + LoadConfig
// ===========================================================================

static void TestConfigParserFull()
{
    mapload::Config cfg{};
    const char* json =
        "{"
        "  \"driver\": \"Engine-ci\\\\Driver\\\\build-x\\\\Driver.sys\","
        "  \"providers\": [\"pte\"],"
        "  \"keep_provider\": true,"
        "  \"cleanup\": false,"
        "  \"canary\": true,"
        "  \"verify\": true,"
        "  \"pause_after_map\": true,"
        "  \"pml4\": \"0x1AD000\""
        "}";
    mapload::Parser p(json);
    CHECK(p.ParseObject(cfg));
    CHECK(cfg.driver == "Engine-ci\\Driver\\build-x\\Driver.sys");
    CHECK(cfg.providers.size() == 1 && cfg.providers[0] == "pte");
    CHECK(cfg.keepProvider && !cfg.cleanup && cfg.canary && cfg.verify
          && cfg.pauseAfterMap);
    CHECK(cfg.pml4 == 0x1AD000ull);
}

static void TestConfigParserDefaults()
{
    mapload::Config cfg{};
    mapload::Parser p("{}");
    CHECK(p.ParseObject(cfg));
    CHECK(!cfg.keepProvider && cfg.cleanup && !cfg.canary && !cfg.verify
          && !cfg.pauseAfterMap);
    CHECK(cfg.pml4 == 0);
    CHECK(cfg.providers.empty());
}

static void TestConfigParserUnknownKey()
{
    mapload::Config cfg{};
    mapload::Parser p("{\"future_key\": {\"nested\": 1}, \"keep_provider\": true}");
    CHECK(p.ParseObject(cfg));
    CHECK(cfg.keepProvider);
}

static void TestConfigParserU64()
{
    mapload::Config cfg{};
    mapload::Parser p("{\"pml4\": 687104}");
    CHECK(p.ParseObject(cfg));
    CHECK(cfg.pml4 == 687104u);

    mapload::Parser q("{\"pml4\": \"0x1AD000\"}");
    CHECK(q.ParseObject(cfg));
    CHECK(cfg.pml4 == 0x1AD000u);

    mapload::Parser r("{\"pml4\": true}");       // bool is not a number
    CHECK(!r.ParseObject(cfg));
}

static void TestConfigParserPml4Edges()
{
    mapload::Config cfg{};

    mapload::Parser a("{\"pml4\": 0x1AD000}");   // unquoted hex
    CHECK(a.ParseObject(cfg) && cfg.pml4 == 0x1AD000u);

    mapload::Parser b("{\"pml4\": \"687104\"}"); // quoted decimal
    CHECK(b.ParseObject(cfg) && cfg.pml4 == 687104);

    // documented product quirk: a quoted empty string parses as 0 (accepted)
    mapload::Parser c("{\"pml4\": \"\"}");
    CHECK(c.ParseObject(cfg) && cfg.pml4 == 0);

    // documented product quirk: overflow returns ULLONG_MAX (errno/ERANGE is
    // not checked; _strtoui64 saturates)
    mapload::Parser d("{\"pml4\": \"18446744073709551616\"}");
    CHECK(d.ParseObject(cfg) && cfg.pml4 == 0xFFFFFFFFFFFFFFFFull);

    // negative and fractional values are rejected
    mapload::Parser e("{\"pml4\": -1}");
    CHECK(!e.ParseObject(cfg));
    mapload::Parser f("{\"pml4\": 1.5}");
    CHECK(!f.ParseObject(cfg));

    // base-0 integer parse: a leading zero is octal (documented quirk)
    mapload::Parser g("{\"pml4\": 010}");
    CHECK(g.ParseObject(cfg) && cfg.pml4 == 8);
}

static void TestConfigParserTrailingGarbage()
{
    // documented product quirk: ParseObject returns at the closing '}' without
    // checking that the input is exhausted, so trailing text is accepted
    mapload::Config cfg{};
    mapload::Parser p("{\"keep_provider\": true}xyz");
    CHECK(p.ParseObject(cfg) && cfg.keepProvider);
}

static void TestConfigParserProvidersAndEscapes()
{
    mapload::Config cfg{};

    mapload::Parser a("{\"providers\": [\"pte\", \"table\"]}");
    CHECK(a.ParseObject(cfg));
    CHECK(cfg.providers.size() == 2 && cfg.providers[0] == "pte"
          && cfg.providers[1] == "table");

    mapload::Parser b("{\"providers\": []}");
    CHECK(b.ParseObject(cfg) && cfg.providers.empty());

    mapload::Parser c("{\"driver\": \"A\\u0042C\\nD\\/E\\\\F\"}");
    CHECK(c.ParseObject(cfg));
    CHECK(cfg.driver == "ABC\nD/E\\F");

    mapload::Parser d("{\"driver\": \"\\u00E9\"}");   // >=0x80 mapped to '?'
    CHECK(d.ParseObject(cfg) && cfg.driver == "?");

    mapload::Parser e("{\"driver\": \"\\q\"}");       // unknown escape
    CHECK(!e.ParseObject(cfg));
}

static void TestConfigParserMalformed()
{
    mapload::Config cfg{};
    mapload::Parser a("");
    CHECK(!a.ParseObject(cfg));                  // not an object

    mapload::Parser b("{\"driver\"}");           // missing ':'
    CHECK(!b.ParseObject(cfg));

    mapload::Parser d("{\"canary\": 12}");       // bad bool
    CHECK(!d.ParseObject(cfg));

    mapload::Parser e("{\"driver\": \"no\\u00zz\"}");   // bad \u escape
    CHECK(!e.ParseObject(cfg));

    mapload::Parser f("{\"providers\": [\"pte\"}");     // unbalanced array
    CHECK(!f.ParseObject(cfg));

    mapload::Parser g("{\"providers\": [\"pte\",]}");   // trailing comma in array
    CHECK(!g.ParseObject(cfg));
}

static void TestLoadConfigTempFile()
{
    char path[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, path);
    std::string file = std::string(path) + "kf_unit_test_config.json";
    {
        std::ofstream out(file.c_str(), std::ios::out | std::ios::trunc);
        out << "{\"providers\": [\"pte\"], \"keep_provider\": true}";
    }
    mapload::Config cfg{};
    CHECK(mapload::LoadConfig(file, cfg));
    CHECK(cfg.loaded);
    CHECK(cfg.path == file);
    CHECK(cfg.providers.size() == 1 && cfg.providers[0] == "pte");
    CHECK(cfg.keepProvider);
    DeleteFileA(file.c_str());

    // explicit request for a nonexistent file -> clean failure
    mapload::Config miss{};
    CHECK(!mapload::LoadConfig(std::string(path) + "kf_unit_test_missing.json", miss));
    CHECK(!miss.loaded);
}

static void TestLoadConfigEdgeFiles()
{
    char path[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, path);

    auto write = [&](const char* name, const void* data, DWORD len) {
        std::string file = std::string(path) + name;
        std::ofstream out(file.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
        out.write(static_cast<const char*>(data), len);
        return file;
    };

    // UTF-8 BOM is stripped before parsing
    const char bomJson[] = "\xEF\xBB\xBF{\"keep_provider\": true}";
    std::string f1 = write("kf_ut_bom.json", bomJson, sizeof(bomJson) - 1);
    mapload::Config c1{};
    CHECK(mapload::LoadConfig(f1, c1));
    CHECK(c1.loaded && c1.keepProvider);
    DeleteFileA(f1.c_str());

    // empty file -> parse failure (not a JSON object)
    std::string f2 = write("kf_ut_empty.json", "", 0);
    mapload::Config c2{};
    CHECK(!mapload::LoadConfig(f2, c2));
    CHECK(!c2.loaded);
    DeleteFileA(f2.c_str());

    // truncated object -> parse failure, cfg not marked loaded
    const char badJson[] = "{";
    std::string f3 = write("kf_ut_bad.json", badJson, sizeof(badJson) - 1);
    mapload::Config c3{};
    CHECK(!mapload::LoadConfig(f3, c3));
    CHECK(!c3.loaded);
    DeleteFileA(f3.c_str());
}

// ===========================================================================
// 3b. mapper/map.cpp — MapImage end to end (fake kernel heap)
// ===========================================================================

// A complete PE32+ image for MapImage: headers, .text (DIR64 target + one
// ntoskrnl import), .reloc (one DIR64), .pdata (nonzero), .rdata (ROT1 table).
// Layout:
//   file 0x000..0x400 headers, .text raw @0x400, .reloc @0x600, .pdata @0x800,
//   .rdata @0xA00; SizeOfImage 0x3000, SizeOfHeaders 0x400, entry 0x1000.
// ROT1-encode a name into one 40-byte table slot (c -> c+1, NUL-padded).
static void PutRot1Name(std::vector<uint8_t>& f, size_t off, const char* plain)
{
    const size_t n = strlen(plain);
    for (size_t i = 0; i < n && i < 39; ++i)
        f[off + i] = static_cast<uint8_t>(plain[i] + 1);
}

static std::vector<uint8_t> BuildMapImagePe()
{
    std::vector<uint8_t> f(0xC00, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(f.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(f.data() + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 4;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.ImageBase = 0x140000000ull;
    nt->OptionalHeader.SizeOfImage = 0x3000;
    nt->OptionalHeader.SizeOfHeaders = 0x400;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x2000, 0x10};
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = {0x1100, 40};

    auto* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec[0].Name, ".text", 6);
    sec[0].VirtualAddress = 0x1000;
    sec[0].Misc.VirtualSize = 0x200;          // keep the entry test unambiguous
    sec[0].SizeOfRawData = 0x200;
    sec[0].PointerToRawData = 0x400;
    sec[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    memcpy(sec[1].Name, ".reloc", 7);
    sec[1].VirtualAddress = 0x2000;
    sec[1].Misc.VirtualSize = 0x200;
    sec[1].SizeOfRawData = 0x200;
    sec[1].PointerToRawData = 0x600;
    sec[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    memcpy(sec[2].Name, ".pdata", 7);
    sec[2].VirtualAddress = 0x2800;
    sec[2].Misc.VirtualSize = 0x100;
    sec[2].SizeOfRawData = 0x100;
    sec[2].PointerToRawData = 0x800;
    sec[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    memcpy(sec[3].Name, ".rdata", 7);
    sec[3].VirtualAddress = 0x2A00;
    sec[3].Misc.VirtualSize = 0x200;
    sec[3].SizeOfRawData = 0x200;
    sec[3].PointerToRawData = 0xA00;
    sec[3].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    // .text: a preferred-base pointer at RVA 0x1010 (relocated by MapImage)
    const uint64_t preferred = 0x140000000ull + 0x1234;
    memcpy(f.data() + 0x410, &preferred, sizeof(preferred));

    // import descriptor at RVA 0x1100, module name 0x1140, by-name 0x1160,
    // IAT 0x1180, ILT 0x1190
    auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(f.data() + 0x500);
    imp->Name = 0x1140;
    imp->OriginalFirstThunk = 0x1190;
    imp->FirstThunk = 0x1180;
    memcpy(f.data() + 0x540, "ntoskrnl.exe", 13);
    auto* byName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(f.data() + 0x560);
    byName->Hint = 1;
    memcpy(byName->Name, "PsLookupProcessByProcessId", 27);
    auto* ilt = reinterpret_cast<IMAGE_THUNK_DATA64*>(f.data() + 0x590);
    ilt[0].u1.AddressOfData = 0x1160;
    ilt[1].u1.AddressOfData = 0;

    // .reloc: one DIR64 for RVA 0x1010
    auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(f.data() + 0x600);
    rel->VirtualAddress = 0x1000;
    rel->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + 1 * sizeof(WORD);
    auto* words = reinterpret_cast<WORD*>(f.data() + 0x600 + sizeof(IMAGE_BASE_RELOCATION));
    words[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x010);

    // .pdata: nonzero payload that StripPdata must zero
    memset(f.data() + 0x800, 0xAA, 0x100);

    // .rdata: an 11-slot ROT1 table (40-byte slots). The scan needle is the
    // ROT1 of "KeInitialize", which is the 10th entry; the fixed scan must
    // anchor at slot 0 and report all 11 slots (440 bytes), not 2 (80 bytes).
    static const char* Rot1Names[11] = {
        "KeQueryActiveProcessors",
        "KeSetSystemAffinityThreadEx",
        "KeRevertToUserAffinityThreadEx",
        "KeGetCurrentProcessorNumberEx",
        "KeStallExecutionProcessor",
        "MmMapIoSpace",
        "MmUnmapIoSpace",
        "KeQueryActiveProcessorCountEx",
        "HalSendNMI",
        "KeInitializeAffinityEx",          // the needle slot
        "KeAddProcessorAffinityEx",
    };
    for (uint32_t i = 0; i < 11; ++i)
        PutRot1Name(f, 0xA00 + i * 40, Rot1Names[i]);

    return f;
}

static void TestMapImageEndToEnd()
{
    const auto file = BuildMapImagePe();

    // PageAlign: raw base is not page-aligned; kbase is rounded up inside the
    // allocation and outAllocationBase stays the KfHeapAlloc return.
    g_Heap.Blocks.clear();
    g_Heap.Next = 0xFFFFF80000000123ull;
    uint64_t base = 0, entry = 0, allocBase = 0, allocSize = 0, rot1Rva = 0;
    uint32_t rot1Size = 0;
    bool independent = true;

    CHECK(mapload::mapper::MapImage(file, &base, &entry, true, &allocBase, &allocSize,
                                    true, false, &independent, &rot1Rva, &rot1Size));
    CHECK(entry == 0x1000);
    CHECK(allocBase == 0xFFFFF80000000123ull);
    CHECK(base == 0xFFFFF80000001000ull);        // rounded up inside the block
    CHECK(allocSize >= 0x3000 + 0xFFF);
    CHECK(!independent);
    CHECK(rot1Rva == 0x2A00 && rot1Size == 440);

    auto* pub = g_Heap.Translate(base, 0x3000);
    CHECK(pub != nullptr);
    if (pub)
    {
        uint16_t magic = 0;
        memcpy(&magic, pub, sizeof(magic));
        CHECK(magic != IMAGE_DOS_SIGNATURE);      // published image is headerless

        uint64_t relocated = 0;
        memcpy(&relocated, pub + 0x1010, sizeof(relocated));
        CHECK(relocated == base + 0x1234);        // preferred pointer + delta

        auto* iat = reinterpret_cast<IMAGE_THUNK_DATA64*>(pub + 0x1180);
        CHECK(iat->u1.Function == 0xFFFFF8012C60001Aull);
        CHECK(strcmp(g_LastResolvedName, "PsLookupProcessByProcessId") == 0);

        CHECK(pub[0x1140] == 0);                  // module name stripped
        const uint8_t zeroDesc[sizeof(IMAGE_IMPORT_DESCRIPTOR)] = {};
        CHECK(memcmp(pub + 0x1100, zeroDesc, sizeof(zeroDesc)) == 0);

        bool relocZero = true, pdataZero = true;
        for (uint32_t i = 0; i < 0x200; ++i)
            if (pub[0x2000 + i]) relocZero = false;
        for (uint32_t i = 0; i < 0x100; ++i)
            if (pub[0x2800 + i]) pdataZero = false;
        CHECK(relocZero);
        CHECK(pdataZero);                          // StripPdata = true
    }

    // Unaligned mode (MAPPED_SAFE payloads): raw base used as-is; .pdata kept.
    g_Heap.Blocks.clear();
    g_Heap.Next = 0xFFFFF80000000201ull;
    CHECK(mapload::mapper::MapImage(file, &base, &entry, false, &allocBase, &allocSize,
                                    false, false, &independent, &rot1Rva, &rot1Size));
    CHECK(base == 0xFFFFF80000000201ull);
    pub = g_Heap.Translate(base, 0x3000);
    CHECK(pub != nullptr);
    if (pub)
    {
        bool pdataNonZero = false;
        for (uint32_t i = 0; i < 0x100; ++i)
            if (pub[0x2800 + i]) pdataNonZero = true;
        CHECK(pdataNonZero);
    }

    // Independent pages: allocated through KfAllocIndependentPages, base as-is.
    g_Heap.Blocks.clear();
    g_Heap.Next = 0xFFFFF80000000333ull;
    CHECK(mapload::mapper::MapImage(file, &base, &entry, true, &allocBase, &allocSize,
                                    true, true, &independent, &rot1Rva, &rot1Size));
    CHECK(independent);
    CHECK(base == 0xFFFFF80000000333ull);
}

static void TestMapImageValidation()
{
    uint64_t base = 0, entry = 0;
    bool independent = false;

    std::vector<uint8_t> tiny(0x10, 0);
    CHECK(!mapload::mapper::MapImage(tiny, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badMZ = BuildMapImagePe();
    badMZ[0] = 0;
    CHECK(!mapload::mapper::MapImage(badMZ, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badPE = BuildMapImagePe();
    badPE[0x40] = 0;                                   // PE signature
    CHECK(!mapload::mapper::MapImage(badPE, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto stripped = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(stripped.data() + 0x40)->FileHeader.Characteristics
        |= IMAGE_FILE_RELOCS_STRIPPED;
    CHECK(!mapload::mapper::MapImage(stripped, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badEntry = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(badEntry.data() + 0x40)
        ->OptionalHeader.AddressOfEntryPoint = 0x1800;  // .PAGE, not executable
    CHECK(!mapload::mapper::MapImage(badEntry, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badSection = BuildMapImagePe();
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(badSection.data() + 0x40);
    IMAGE_FIRST_SECTION(nt)[0].PointerToRawData = 0xFF00;   // past the file
    CHECK(!mapload::mapper::MapImage(badSection, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badLfanew = BuildMapImagePe();
    reinterpret_cast<IMAGE_DOS_HEADER*>(badLfanew.data())->e_lfanew = 0x7FFFFFFF;
    CHECK(!mapload::mapper::MapImage(badLfanew, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto pe32 = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(pe32.data() + 0x40)
        ->OptionalHeader.Magic = 0x10B;                    // PE32, not PE32+
    CHECK(!mapload::mapper::MapImage(pe32, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto zeroImage = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(zeroImage.data() + 0x40)
        ->OptionalHeader.SizeOfImage = 0;
    CHECK(!mapload::mapper::MapImage(zeroImage, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto hugeImage = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(hugeImage.data() + 0x40)
        ->OptionalHeader.SizeOfImage = 0x20000000;
    CHECK(!mapload::mapper::MapImage(hugeImage, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto noSections = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(noSections.data() + 0x40)
        ->FileHeader.NumberOfSections = 0;
    CHECK(!mapload::mapper::MapImage(noSections, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto tooManySections = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(tooManySections.data() + 0x40)
        ->FileHeader.NumberOfSections = 97;
    CHECK(!mapload::mapper::MapImage(tooManySections, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));

    auto badHeaders = BuildMapImagePe();
    reinterpret_cast<IMAGE_NT_HEADERS64*>(badHeaders.data() + 0x40)
        ->OptionalHeader.SizeOfHeaders = 0x100;             // does not cover NT headers
    CHECK(!mapload::mapper::MapImage(badHeaders, &base, &entry, true, nullptr, nullptr,
                                     false, false, &independent, nullptr, nullptr));
}

static std::string TestExeDir()
{
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (char* sep = strrchr(path, '\\')) *sep = 0;
    return path;
}

static void TestLoadConfigDefaultSearchOrder()
{
    char tmp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmp);
    const std::string ws = std::string(tmp) + "kf_ut_ws";
    CreateDirectoryA(ws.c_str(), nullptr);
    const std::string wsFile = ws + "\\mapload.json";

    auto writeFile = [](const std::string& path, const char* text) {
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        out << text;
    };

    // 1. workspace mapload.json wins
    writeFile(wsFile, "{\"keep_provider\": true}");
    strcpy_s(mapload::g_TestWorkspaceRoot, ws.c_str());
    mapload::Config c1{};
    CHECK(mapload::LoadConfig("", c1));
    CHECK(c1.loaded);
    CHECK(c1.path == wsFile);
    CHECK(c1.keepProvider);

    // 2. a malformed workspace file is a hard failure (no exe-dir fallback)
    writeFile(wsFile, "{");
    mapload::Config c2{};
    CHECK(!mapload::LoadConfig("", c2));
    CHECK(!c2.loaded);

    // 3. no file anywhere -> defaults, not an error
    DeleteFileA(wsFile.c_str());
    mapload::Config c3{};
    CHECK(mapload::LoadConfig("", c3));
    CHECK(!c3.loaded);
    CHECK(c3.driver.empty());

    // 4. exe-dir fallback when the workspace has no mapload.json
    const std::string exeFile = TestExeDir() + "\\mapload.json";
    const bool preexisting = GetFileAttributesA(exeFile.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (!preexisting)
    {
        writeFile(exeFile, "{\"keep_provider\": true}");
        mapload::Config c4{};
        CHECK(mapload::LoadConfig("", c4));
        CHECK(c4.loaded);
        CHECK(c4.path == exeFile);
        CHECK(c4.keepProvider);
        DeleteFileA(exeFile.c_str());
    }

    mapload::g_TestWorkspaceRoot[0] = '\0';
    RemoveDirectoryA(ws.c_str());
}

// ===========================================================================
// 4. controller/pure.h — extracted bootstrap helpers
// ===========================================================================

static void TestIsAbsolutePathAndJoin()
{
    CHECK(mapload::IsAbsolutePath("C:\\x"));
    CHECK(mapload::IsAbsolutePath("C:/x"));
    CHECK(mapload::IsAbsolutePath("\\\\server\\share"));
    // documented product semantics (Windows disagrees on both):
    // a single-rooted path is NOT treated as absolute; a drive-relative path IS
    CHECK(!mapload::IsAbsolutePath("\\x"));
    CHECK(mapload::IsAbsolutePath("C:x"));
    CHECK(mapload::IsAbsolutePath("C:"));
    CHECK(!mapload::IsAbsolutePath("x\\y"));
    CHECK(!mapload::IsAbsolutePath(""));

    CHECK(mapload::JoinPath("C:\\root", "a\\b") == "C:\\root\\a\\b");
    CHECK(mapload::JoinPath("C:\\root", "D:\\abs") == "D:\\abs");
    CHECK(mapload::JoinPath("", "a\\b") == "a\\b");
    // documented quirk: a trailing backslash is not collapsed
    CHECK(mapload::JoinPath("C:\\root\\", "a") == "C:\\root\\\\a");
}

static void TestPostboxSectionHandoffValid()
{
    PostboxSectionHandoff h{};
    h.Magic = PostboxSectionHandoffMagic;
    h.Version = PostboxSectionHandoffVersion;
    h.Pid = 1;
    h.MailboxVa = 0x10000;
    h.SessionId = 1;
    h.CreateTime = 1;
    CHECK(mapload::PostboxSectionHandoffValid(h));

    h.Magic = 0;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
    h.Magic = PostboxSectionHandoffMagic;

    h.Version = PostboxSectionHandoffVersion + 1;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
    h.Version = PostboxSectionHandoffVersion;

    h.Pid = 0;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
    h.Pid = 1;

    h.SessionId = 0;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
    h.SessionId = 1;

    h.CreateTime = 0;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
    h.CreateTime = 1;

    h.MailboxVa = 0x10004;                     // not 8-byte aligned
    CHECK(!mapload::PostboxSectionHandoffValid(h));

    h.MailboxVa = mapload::kPostboxUserLimit - PostboxBytes;   // exact edge
    CHECK(mapload::PostboxSectionHandoffValid(h));
    h.MailboxVa = mapload::kPostboxUserLimit - PostboxBytes + 8;
    CHECK(!mapload::PostboxSectionHandoffValid(h));
}

static void TestParseU64Arg()
{
    uint64_t v = 0;
    CHECK(mapload::ParseU64Arg("0x1234", v) && v == 0x1234);
    CHECK(mapload::ParseU64Arg("4660", v) && v == 4660);
    CHECK(mapload::ParseU64Arg("0X10", v) && v == 16);
    CHECK(mapload::ParseU64Arg("0", v) && v == 0);
    CHECK(!mapload::ParseU64Arg("0x", v));
    CHECK(!mapload::ParseU64Arg("", v));
    CHECK(!mapload::ParseU64Arg("1234xyz", v));
    CHECK(!mapload::ParseU64Arg(nullptr, v));
    // documented product quirk: _strtoui64 saturates on overflow (ERANGE is
    // not checked), so an out-of-range value parses as ULLONG_MAX
    CHECK(mapload::ParseU64Arg("18446744073709551616", v) && v == 0xFFFFFFFFFFFFFFFFull);
}

static void TestPostboxHash()
{
    // Pinned values of the custom FNV-1a variant (offset 1469598103934665603,
    // not the standard 14695981039346656037).
    CHECK(mapload::PostboxHashBytes(nullptr, 0) == 0x14650fb0739d0383ull);
    const uint8_t one[1] = {0x00};
    CHECK(mapload::PostboxHashBytes(one, 1) == 0x44bd2bd473ccf799ull);

    std::vector<uint8_t> fixture(0x40);
    for (uint32_t i = 0; i < 0x40; ++i) fixture[i] = static_cast<uint8_t>(i);
    const uint64_t h = mapload::PostboxHashBytes(fixture.data(), fixture.size());
    CHECK(h == 0xcf7236ee29d93e83ull);

    const char* reason = "sentinel";
    CHECK(mapload::PostboxMarkerPresent(fixture, h, &reason));
    CHECK(reason == nullptr);

    reason = "sentinel";
    CHECK(!mapload::PostboxMarkerPresent(fixture, h ^ 1, &reason));
    CHECK(reason && strcmp(reason, "build hash mismatch") == 0);

    std::vector<uint8_t> tiny(0x10, 0);
    reason = "sentinel";
    CHECK(!mapload::PostboxMarkerPresent(tiny, 0, &reason));
    CHECK(reason && strcmp(reason, "file is too small for a PE header") == 0);
}

static void TestResolveDriverPath()
{
    const std::string root = "C:\\repo";
    CHECK(mapload::ResolveDriverPath("C:\\cli.sys", false, root, "", false, false)
          == "C:\\cli.sys");
    CHECK(mapload::ResolveDriverPath("", true, root, "cfg\\D.sys", false, false)
          == "C:\\repo\\Engine-ci\\Driver\\build-postbox-release\\Driver.sys");
    CHECK(mapload::ResolveDriverPath("", false, root, "cfg\\D.sys", false, false)
          == "C:\\repo\\cfg\\D.sys");
    CHECK(mapload::ResolveDriverPath("", false, root, "", true, false)
          == "C:\\repo\\Engine-ci\\Driver\\build-nohook-release\\Driver.sys");
    CHECK(mapload::ResolveDriverPath("", false, root, "", false, true)
          == "C:\\repo\\Engine-ci\\Driver\\build-nohook-debug\\Driver.sys");
    CHECK(mapload::ResolveDriverPath("", false, root, "", false, false)
          == "C:\\repo\\Engine-ci\\Driver\\build\\Driver.sys");
    // the CLI override wins even when a postbox default exists
    CHECK(mapload::ResolveDriverPath("D:\\x.sys", true, root, "cfg", true, true)
          == "D:\\x.sys");
}

static void TestFillPostboxImageLayout()
{
    const auto file = BuildMapImagePe();
    PostboxImageLayout L{};
    CHECK(mapload::FillPostboxImageLayout(file, 0x1000, 0x2000, 0x3000, &L));
    CHECK(L.Magic == PostboxLayoutMagic);
    CHECK(L.Version == PostboxLayoutVersion);
    CHECK(L.ImageSize == 0x3000);
    CHECK(L.RawBase == 0x1000 && L.ImageBase == 0x2000 && L.AllocSize == 0x3000);
    CHECK(L.SectionCount == 5);                // header + 4 PE sections
    CHECK(L.Sections[0].Rva == 0 && L.Sections[0].Size == 0x400);
    CHECK(L.Sections[0].Flags == PostboxPageRNx);

    bool textRx = false, pdataRNx = false, rdataRNx = false;
    for (uint32_t i = 1; i < L.SectionCount; ++i)
    {
        if (L.Sections[i].Rva == 0x1000 && L.Sections[i].Flags == PostboxPageRx) textRx = true;
        if (L.Sections[i].Rva == 0x2800 && L.Sections[i].Flags == PostboxPageRNx) pdataRNx = true;
        if (L.Sections[i].Rva == 0x2A00 && L.Sections[i].Flags == PostboxPageRNx) rdataRNx = true;
    }
    CHECK(textRx);
    CHECK(pdataRNx);
    CHECK(rdataRNx);

    auto bad = file;
    bad[0] = 0;                                 // not MZ
    CHECK(!mapload::FillPostboxImageLayout(bad, 0, 0, 0, &L));

    auto pe32 = file;
    reinterpret_cast<IMAGE_NT_HEADERS64*>(pe32.data() + 0x40)
        ->OptionalHeader.Magic = 0x10B;         // PE32, not PE32+
    CHECK(!mapload::FillPostboxImageLayout(pe32, 0, 0, 0, &L));

    auto badSize = file;
    reinterpret_cast<IMAGE_NT_HEADERS64*>(badSize.data() + 0x40)
        ->OptionalHeader.SizeOfImage = 0;
    CHECK(!mapload::FillPostboxImageLayout(badSize, 0, 0, 0, &L));
}

static void TestWorkspaceRootWalk()
{
    // The walk starts at the executable's directory and returns the parent of
    // the first "out" directory that owns a "build" directory.
    auto isBuildDir = [](const std::string& p) {
        return p == "C:\\repo\\out\\build";
    };
    CHECK(mapload::FindWorkspaceRootFromExe(
              "C:\\repo\\out\\build\\release\\mapload\\mapload.exe", isBuildDir)
          == "C:\\repo");

    // exe outside the cmake tree -> exe directory
    CHECK(mapload::FindWorkspaceRootFromExe("D:\\tools\\mapload.exe", isBuildDir)
          == "D:\\tools");

    // an "out" directory without "build" is skipped; the walk continues upward
    auto noBuild = [](const std::string&) { return false; };
    CHECK(mapload::FindWorkspaceRootFromExe(
              "C:\\repo\\out\\build\\x\\mapload.exe", noBuild)
          == "C:\\repo\\out\\build\\x");
}

// ===========================================================================
// 5. controller/pure.h — ROT1 table head, page protection, section zeroing,
//    image/config-page teardown
// ===========================================================================

static void TestFindRot1Table()
{
    // The needle is ROT1("KeInitialize") and sits in the 10th slot; the scan
    // must anchor at the table head and report all 11 slots.
    std::vector<uint8_t> buf(0x400, 0);
    static const char* Names[11] = {
        "KeQueryActiveProcessors",
        "KeSetSystemAffinityThreadEx",
        "KeRevertToUserAffinityThreadEx",
        "KeGetCurrentProcessorNumberEx",
        "KeStallExecutionProcessor",
        "MmMapIoSpace",
        "MmUnmapIoSpace",
        "KeQueryActiveProcessorCountEx",
        "HalSendNMI",
        "KeInitializeAffinityEx",
        "KeAddProcessorAffinityEx",
    };
    for (uint32_t i = 0; i < 11; ++i)
        PutRot1Name(buf, 0x100 + i * 40, Names[i]);

    uint64_t rva = 0xDEAD;
    uint32_t size = 0xDEAD;
    CHECK(mapload::FindRot1Table(buf.data(), buf.size(), &rva, &size));
    CHECK(rva == 0x100);
    CHECK(size == 440);

    // no needle -> false and outputs zeroed
    std::vector<uint8_t> none(0x400, 0xAA);
    rva = 0xDEAD;
    size = 0xDEAD;
    CHECK(!mapload::FindRot1Table(none.data(), none.size(), &rva, &size));
    CHECK(rva == 0 && size == 0);

    // a lone needle + successor (legacy 2-slot table) still reports just those
    // slots when the preceding 40 bytes are not a valid name
    std::vector<uint8_t> shortTable(0x400, 0);
    shortTable[0x1D8] = 0x01;                 // non-printable guard before the table
    PutRot1Name(shortTable, 0x200, "KeInitializeAffinityEx");
    PutRot1Name(shortTable, 0x228, "KeAddProcessorAffinityEx");
    rva = 0xDEAD;
    size = 0xDEAD;
    CHECK(mapload::FindRot1Table(shortTable.data(), shortTable.size(), &rva, &size));
    CHECK(rva == 0x200 && size == 80);

    // null image / null outputs are safe
    CHECK(!mapload::FindRot1Table(nullptr, 0, nullptr, nullptr));
}

static void TestPostboxPageProtection()
{
    CHECK(mapload::PostboxPageProtection(PostboxPageRx) == PAGE_EXECUTE_READ);
    CHECK(mapload::PostboxPageProtection(PostboxPageRwNx) == PAGE_READWRITE);
    CHECK(mapload::PostboxPageProtection(PostboxPageRNx) == PAGE_READONLY);
    CHECK(mapload::PostboxPageProtection(0xFF) == PAGE_READONLY);
}

static void TestZeroSectionByName()
{
    std::vector<uint8_t> image(0x2000, 0);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x40;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + 0x40);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    memcpy(sec[0].Name, ".reloc", 7);
    sec[0].VirtualAddress = 0x1800;
    sec[0].Misc.VirtualSize = 0x100;
    memcpy(sec[1].Name, ".pdata", 7);
    sec[1].VirtualAddress = 0x1900;
    sec[1].Misc.VirtualSize = 0x80;
    memcpy(sec[2].Name, ".data", 6);
    sec[2].VirtualAddress = 0x1A00;
    sec[2].Misc.VirtualSize = 0;               // falls back to SizeOfRawData
    sec[2].SizeOfRawData = 0x40;
    memset(image.data() + 0x1800, 0xAA, 0x100);
    memset(image.data() + 0x1900, 0xAA, 0x80);
    memset(image.data() + 0x1A00, 0xAA, 0x40);

    uint32_t rva = 0;
    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".reloc", &rva)
          == 0x100);
    CHECK(rva == 0x1800);
    bool relocZero = true;
    for (uint32_t i = 0; i < 0x100; ++i)
        if (image[0x1800 + i]) relocZero = false;
    CHECK(relocZero);
    CHECK(image[0x1900] == 0xAA);              // .pdata untouched by the .reloc call

    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".pdata", &rva)
          == 0x80);
    CHECK(rva == 0x1900);
    CHECK(image[0x1A00] == 0xAA);

    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".data", &rva)
          == 0x40);                              // VirtualSize 0 -> RawSize
    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".nope", &rva)
          == 0);

    // a section starting past the image is a no-op; one crossing the end is clamped
    sec[0].VirtualAddress = 0x2000;
    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".reloc", &rva)
          == 0);
    sec[0].VirtualAddress = 0x1FF0;
    sec[0].Misc.VirtualSize = 0x100;
    CHECK(mapload::ZeroSectionByName(image.data(), image.size(), sec, 3, ".reloc", &rva)
          == 0x10);
}

struct FreeRecorder
{
    int Writes = 0, Sets = 0, FreeIndep = 0, FreePool = 0, Logs = 0;
    uint64_t WriteBase = 0, SetBase = 0, FreeIndepBase = 0, FreePoolBase = 0;
    size_t WriteSize = 0, SetSize = 0, FreeIndepSize = 0;
    bool WriteAllZero = true;
    bool WriteOk = true;
    bool SetOk = true;
};

static void TestFreeMappedImageZeroed()
{
    auto run = [](FreeRecorder& r, uint64_t base, uint64_t size, bool independent) {
        mapload::FreeMappedImageZeroed(
            base, size, independent,
            [&r](uint64_t b, const void* d, size_t s) {
                ++r.Writes; r.WriteBase = b; r.WriteSize = s;
                const uint8_t* p = static_cast<const uint8_t*>(d);
                for (size_t i = 0; i < s; ++i)
                    if (p[i]) r.WriteAllZero = false;
                return r.WriteOk;
            },
            [&r](uint64_t b, size_t s) {
                ++r.Sets; r.SetBase = b; r.SetSize = s;
                return r.SetOk;
            },
            [&r](uint64_t b, size_t s) {
                ++r.FreeIndep; r.FreeIndepBase = b; r.FreeIndepSize = s;
            },
            [&r](uint64_t b) { ++r.FreePool; r.FreePoolBase = b; },
            [&r](const char*) { ++r.Logs; });
    };

    {
        FreeRecorder r;
        run(r, 0x1000, 0x2000, true);
        CHECK(r.Writes == 1 && r.WriteBase == 0x1000 && r.WriteSize == 0x2000);
        CHECK(r.WriteAllZero);
        CHECK(r.Sets == 0 && r.FreePool == 0);
        CHECK(r.FreeIndep == 1 && r.FreeIndepBase == 0x1000 && r.FreeIndepSize == 0x2000);
        CHECK(r.Logs == 0);
    }
    {
        FreeRecorder r;
        run(r, 0x2000, 0x1000, false);
        CHECK(r.Sets == 1 && r.SetBase == 0x2000 && r.SetSize == 0x1000);
        CHECK(r.FreePool == 1 && r.FreePoolBase == 0x2000);
        CHECK(r.Writes == 0 && r.FreeIndep == 0);
        CHECK(r.Logs == 0);
    }
    {
        // Base == 0 -> no calls at all
        FreeRecorder r;
        run(r, 0, 0x1000, false);
        CHECK(r.Writes == 0 && r.Sets == 0 && r.FreeIndep == 0 && r.FreePool == 0);
    }
    {
        // size 0 -> free without wiping
        FreeRecorder r;
        run(r, 0x3000, 0, true);
        CHECK(r.Writes == 0 && r.FreeIndep == 1 && r.FreeIndepSize == 0);
    }
    {
        // wipe failures still free, and log
        FreeRecorder r;
        r.WriteOk = false;
        run(r, 0x4000, 0x1000, true);
        CHECK(r.Writes == 1 && r.FreeIndep == 1 && r.Logs == 1);

        FreeRecorder p;
        p.SetOk = false;
        run(p, 0x5000, 0x1000, false);
        CHECK(p.Sets == 1 && p.FreePool == 1 && p.Logs == 1);
    }
}

static void TestCreatePostboxConfigPage()
{
    PostboxConfig cfg{};
    cfg.Magic = PostboxConfigMagic;
    cfg.Version = PostboxConfigVersion;
    cfg.Key[0] = 0x42;

    struct Rec
    {
        int Allocs = 0, Copies = 0, Protects = 0, Frees = 0;
        size_t AllocSize = 0, CopySize = 0, ProtectSize = 0;
        PVOID Page = nullptr;
        const void* CopySrc = nullptr;
        ULONG Protect = 0;
        bool CopyOk = true;
        bool ProtectOk = true;
    };

    auto run = [](Rec& r, PostboxConfig& c, PVOID page) {
        return mapload::CreatePostboxConfigPage(
            c,
            [&r, page](size_t s) { ++r.Allocs; r.AllocSize = s; r.Page = page; return page; },
            [&r](PVOID p, const void* src, size_t s) {
                ++r.Copies; r.CopySrc = src; r.CopySize = s;
                return r.CopyOk && p == r.Page;
            },
            [&r](PVOID p, size_t s, ULONG prot) {
                ++r.Protects; r.ProtectSize = s; r.Protect = prot;
                return r.ProtectOk && p == r.Page;
            },
            [&r](PVOID p, size_t s) {
                ++r.Frees; (void) s; (void) p;
            });
    };

    {
        Rec r;
        const PVOID page = reinterpret_cast<PVOID>(0x5000);
        PVOID got = run(r, cfg, page);
        CHECK(got == page);
        CHECK(r.Allocs == 1 && r.AllocSize == 0x1000);
        CHECK(r.Copies == 1 && r.CopySize == sizeof(PostboxConfig));
        CHECK(r.CopySrc == &cfg);
        CHECK(r.Protects == 1 && r.ProtectSize == 0x1000 && r.Protect == PAGE_READWRITE);
        CHECK(r.Frees == 0);
    }
    {
        Rec r;
        r.CopyOk = false;
        CHECK(run(r, cfg, reinterpret_cast<PVOID>(0x5000)) == nullptr);
        CHECK(r.Copies == 1 && r.Protects == 0 && r.Frees == 1);
    }
    {
        Rec r;
        r.ProtectOk = false;
        CHECK(run(r, cfg, reinterpret_cast<PVOID>(0x5000)) == nullptr);
        CHECK(r.Copies == 1 && r.Protects == 1 && r.Frees == 1);
    }
    {
        Rec r;
        CHECK(run(r, cfg, nullptr) == nullptr);
        CHECK(r.Allocs == 1 && r.Copies == 0 && r.Protects == 0 && r.Frees == 0);
    }
}

static void TestFreePostboxConfigPage()
{
    struct Rec
    {
        int Sets = 0, Frees = 0, Logs = 0;
        PVOID SetPage = nullptr, FreePage = nullptr;
        size_t SetSize = 0, FreeSize = 0;
        bool SetOk = true;
    };
    auto run = [](Rec& r, PVOID page) {
        mapload::FreePostboxConfigPage(
            page,
            [&r](PVOID p, size_t s) { ++r.Sets; r.SetPage = p; r.SetSize = s; return r.SetOk; },
            [&r](PVOID p, size_t s) { ++r.Frees; r.FreePage = p; r.FreeSize = s; },
            [&r](const char*) { ++r.Logs; });
    };

    {
        Rec r;
        run(r, nullptr);
        CHECK(r.Sets == 0 && r.Frees == 0 && r.Logs == 0);
    }
    {
        Rec r;
        const PVOID page = reinterpret_cast<PVOID>(0x6000);
        run(r, page);
        CHECK(r.Sets == 1 && r.SetPage == page && r.SetSize == 0x1000);
        CHECK(r.Frees == 1 && r.FreePage == page && r.FreeSize == 0x1000);
        CHECK(r.Logs == 0);
    }
    {
        Rec r;
        r.SetOk = false;
        run(r, reinterpret_cast<PVOID>(0x6000));
        CHECK(r.Sets == 1 && r.Frees == 1 && r.Logs == 1);
    }
}

// ===========================================================================
// harness
// ===========================================================================

static void RunMaploadUnitTests()
{
    TestRangeInImage();
    TestApplyRelocs();
    TestApplyRelocsRejects();
    TestApplyRelocsEmptyDirectory();
    TestApplyRelocsHighlow();

    TestResolveImportsOk();
    TestResolveImportsRejects();
    TestResolveImportsRejectsExpanded();
    TestStripImportMetadata();
    TestStripImportMetadataOftZero();

    TestMapImageEndToEnd();
    TestMapImageValidation();

    TestConfigParserFull();
    TestConfigParserDefaults();
    TestConfigParserUnknownKey();
    TestConfigParserU64();
    TestConfigParserPml4Edges();
    TestConfigParserTrailingGarbage();
    TestConfigParserProvidersAndEscapes();
    TestConfigParserMalformed();
    TestLoadConfigTempFile();
    TestLoadConfigEdgeFiles();
    TestLoadConfigDefaultSearchOrder();

    TestIsAbsolutePathAndJoin();
    TestPostboxSectionHandoffValid();
    TestParseU64Arg();
    TestPostboxHash();
    TestResolveDriverPath();
    TestFillPostboxImageLayout();
    TestWorkspaceRootWalk();

    TestFindRot1Table();
    TestPostboxPageProtection();
    TestZeroSectionByName();
    TestFreeMappedImageZeroed();
    TestCreatePostboxConfigPage();
    TestFreePostboxConfigPage();
}

int main()
{
    RunMaploadUnitTests();
    std::printf("\n==== kf_mapload_tests: %u passed, %u failed ====\n",
                g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
