// Pattern parsing and PE image scanning: 'AA BB ??' signature strings to byte arrays, byte scans over
// image sections, and export-table walks. Pure byte/PE parsing, no kernel memory access happens here

// Self-implemented string/byte helpers. The scan path must not pull CRT routines into the import
// table: strlen/strcmp/memcmp are exported by ntoskrnl and would be listed next to DbgPrintEx,
// which is exactly the kind of import the trace cleaners are meant to avoid
static size_t StringLength(const char* String)
{
    size_t Length = 0;
    while (String[Length]) ++Length;
    return Length;
}

static bool StringEquals(const char* Left, const char* Right)
{
    while (*Left && *Left == *Right)
    {
        ++Left;
        ++Right;
    }
    return *Left == *Right;
}

static bool BytesEqual(const void* Left, const void* Right, size_t Size)
{
    auto A = (const uint8_t*) Left;
    auto B = (const uint8_t*) Right;
    for (size_t i = 0; i < Size; ++i)
        if (A[i] != B[i]) return false;
    return true;
}

// Wide variants for the module/process name comparisons (wcslen/wcscmp are ntoskrnl exports too)
static size_t WideStringLength(const wchar_t* String)
{
    size_t Length = 0;
    while (String[Length]) ++Length;
    return Length;
}

static bool WideStringEquals(const wchar_t* Left, const wchar_t* Right)
{
    while (*Left && *Left == *Right)
    {
        ++Left;
        ++Right;
    }
    return *Left == *Right;
}

// A binary signature plus its true byte count. Patterns cannot be NUL-terminated: real instruction
// bytes include 00, so a terminator would silently shorten the scan.
template<size_t N>
struct Pattern
{
    std::array<char, N> Bytes;
    size_t Length;
    bool Valid;

    const char *data() const { return Bytes.data(); }
};

// Compile-time check used by Strings.h: a pattern with an invalid hex token must
// fail the build instead of silently becoming a 0xFF byte at scan time.
template<size_t N>
constexpr bool PatternIsValid(const Pattern<N> &P) { return P.Valid; }

// Encode/decode a whole pattern, preserving the length and validity that
// PatternToBytes computed. The byte array is XORed exactly like a string; only
// the length/validity are carried separately.
template<size_t N>
constexpr Pattern<N> EncodeBytes(const Pattern<N> &In)
{
    return {XorSeed(In.Bytes), In.Length, In.Valid};
}

template<size_t N>
constexpr Pattern<N> Decode(const Pattern<N> &In)
{
    return {XorSeed(In.Bytes), In.Length, In.Valid};
}

// Hex to bytes
constexpr uint8_t HexToByte(char c) {
    return (c >= '0' && c <= '9') ? c - '0' :
           (c >= 'A' && c <= 'F') ? c - 'A' + 0xA :
           (c >= 'a' && c <= 'f') ? c - 'a' + 0xA :
           0xFF; // Invalid
}

// Pattern to Bytes: each '?' or hex pair consumes two characters, so single-space-separated
// tokens like "AA ? BB" come out one byte each
template<size_t N>
constexpr Pattern<N> PatternToBytes(const char (&Signature)[N])
{
    std::array<char, N> Bytes{};
    size_t i = 0;
    size_t len = 0;
    bool valid = true;

    while (i < N - 1)
    {
        if (Signature[i] == ' ') { ++i; continue; }
        if (Signature[i] == '?') { Bytes[len++] = '?'; i += 2; continue; }

        // A hex token must have two valid digits. 0xFF is the invalid sentinel;
        // accepting it silently would turn a typo into a real 0xFF byte.
        const uint8_t hi = HexToByte(Signature[i]);
        const uint8_t lo = HexToByte(Signature[i + 1]);
        if (hi == 0xFF || lo == 0xFF) valid = false;

        Bytes[len++] = static_cast<char>(hi << 4 | lo);
        i += 2;
    }

    Bytes[len] = '\0';
    return {Bytes, len, valid};
}

// True if the signature matches at Current ('?' matches any byte)
static bool Matches(const char *Current, const char *Signature, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (Signature[i] != '?' && Signature[i] != Current[i])
            return false;
    return true;
}

// Per-scan address dumps are debug-only noise on a normal load; flip this when a signature miss needs
// the exact range that was searched
constexpr bool VerboseScan = false;

// Signature scan over a range. This is intentionally quiet: ScanModuleImage tries .PAGE and then
// .text and logs one result after all section attempts are done
address SignatureScan(const void *StartAddress, const void *EndAddress, const char *Signature, size_t Size)
{
    if constexpr (VerboseScan)
    {
        print(INFO("Start Address: %p"), StartAddress);
        print(INFO("End Address: %p"), EndAddress);
        print(INFO("Signature Address: %p"), Signature);
    }
    size_t size = Size;

    // Nothing to search: a missing range, or one shorter than the signature (the bound below would wrap)
    if (!StartAddress || !EndAddress || !Signature || !size ||
        (size_t) EndAddress - (size_t) StartAddress < size)
    {
        return nullptr;
    }

    // First-byte reject: the earliest non-wildcard byte of the signature. A position where it differs
    // cannot match, so the full compare only runs where it hits — for a concrete first byte roughly
    // one position in 256. The whole compare below is still what decides, so the leftmost match is
    // unchanged. An all-wildcard signature (First == size) keeps matching at the first position,
    // exactly as before
    size_t First = 0;
    while (First < size && Signature[First] == '?') ++First;

    for (const char *Current = (char *) StartAddress; Current <= (char *) ((size_t) EndAddress - size); ++Current)
    {
        // In range by construction: First < size, and the loop bound holds Current + size <= EndAddress
        if (First < size && Current[First] != Signature[First]) continue;
        if (Matches(Current, Signature, size))
            return Current;
    }

    return nullptr;
}

// Pattern scan over one image section
address SectionScan(address BaseAddress, const char *SectionName, const char *Signature, size_t Size)
{
    // Get section
    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionalHeader = &ntHeader->OptionalHeader;
    auto sectionHeader = (_IMAGE_SECTION_HEADER *) ((uint64_t) optionalHeader + sizeof(_IMAGE_OPTIONAL_HEADER64));

    // loop
    void *sectionStart{};
    void *sectionEnd{};

    // Find Section
    size_t NameLen = StringLength(SectionName);
    for (int i = 0; i < fileHeader->NumberOfSections; i++)
    {
        if (BytesEqual(sectionHeader[i].Name, SectionName, NameLen))
        {
            sectionStart = BaseAddress + sectionHeader[i].VirtualAddress;
            sectionEnd = BaseAddress + sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Section not found: there is nothing to scan; ScanModuleImage falls back to the next section
    if (!sectionStart)
        return nullptr;

    // Signature Scan
    return SignatureScan(sectionStart, sectionEnd, Signature, Size);
}

// Lazy Import: resolves a name through the image's export table, so no import table entries are
// created (data exports come back as the variable's address)
address FindFuncExports(address BaseAddress, const char *FuncName)
{
    if (!BaseAddress) return nullptr;

    // DataDirectory[0] is the export directory; an image without one has nothing to resolve
    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    auto &dataDir = ntHeader->OptionalHeader.DataDirectory[0];
    if (!dataDir.VirtualAddress) return nullptr;

    auto exportDir = (_IMAGE_EXPORT_DIRECTORY *) (BaseAddress + dataDir.VirtualAddress);
    uint32_t *functions = (uint32_t *) (BaseAddress + exportDir->AddressOfFunctions);
    uint16_t *ordinals = (uint16_t *) (BaseAddress + exportDir->AddressOfNameOrdinals);
    uint32_t *names = (uint32_t *) (BaseAddress + exportDir->AddressOfNames);

    // Loop through export table
    for (uint32_t i = 0; i < exportDir->NumberOfNames; ++i)
    {
        const char *funcName = (const char *) (BaseAddress + names[i]);
        if (StringEquals(funcName, FuncName))
            return BaseAddress + functions[ordinals[i]];
    }

    print(ERROR("EXPORT FUNCTION NOT FOUND!"));
    return nullptr;
}

// Batch variant for callers resolving several symbols at once: ONE walk of the export table
// fills Results[i] for Names[i] (a name not exported leaves that slot null), instead of
// re-walking the whole table per name like the single lookup above
void FindFuncExportsBatch(address BaseAddress, const char *const *Names, address *Results, uint32_t Count)
{
    for (uint32_t i = 0; i < Count; ++i)
        Results[i] = nullptr;

    if (!BaseAddress) return;

    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    auto &dataDir = ntHeader->OptionalHeader.DataDirectory[0];
    if (!dataDir.VirtualAddress) return;

    auto exportDir = (_IMAGE_EXPORT_DIRECTORY *) (BaseAddress + dataDir.VirtualAddress);
    uint32_t *functions = (uint32_t *) (BaseAddress + exportDir->AddressOfFunctions);
    uint16_t *ordinals = (uint16_t *) (BaseAddress + exportDir->AddressOfNameOrdinals);
    uint32_t *names = (uint32_t *) (BaseAddress + exportDir->AddressOfNames);

    // One pass over the exports, stopping once everything on the wanted list is found. The
    // wanted list is a handful of names, so the inner compare loop is negligible next to the
    // table walk it saves
    uint32_t Missing = Count;
    for (uint32_t i = 0; i < exportDir->NumberOfNames && Missing; ++i)
    {
        const char *funcName = (const char *) (BaseAddress + names[i]);

        for (uint32_t j = 0; j < Count; ++j)
        {
            if (!Results[j] && StringEquals(funcName, Names[j]))
            {
                Results[j] = BaseAddress + functions[ordinals[i]];
                Missing--;
                break;
            }
        }
    }
}

#ifdef DEBUG
// Debug-only self-test (DriverEntry step 0.9): the lazy export walk must agree
// with the loader's import slots for data exports, return null for a missing
// name, and fill a batch with the same results.
bool VerifyFindFuncExports(address NtoskrnlBase)
{
    if (!NtoskrnlBase)
    {
        print(ERROR("VerifyFindFuncExports: no ntoskrnl base"));
        return false;
    }

    bool Ok = true;
    const address ExpectedInitial = (address) (uintptr_t) __imp_PsInitialSystemProcess;
    const address ExpectedLoaded = (address) (uintptr_t) __imp_PsLoadedModuleList;

    const address Initial = FindFuncExports(NtoskrnlBase, "PsInitialSystemProcess");
    if (!Initial || Initial != ExpectedInitial)
    {
        print(ERROR("VerifyFindFuncExports: PsInitialSystemProcess %p != import %p"),
              (void*) (uintptr_t) Initial, (void*) (uintptr_t) ExpectedInitial);
        Ok = false;
    }

    const address Loaded = FindFuncExports(NtoskrnlBase, "PsLoadedModuleList");
    if (!Loaded || Loaded != ExpectedLoaded)
    {
        print(ERROR("VerifyFindFuncExports: PsLoadedModuleList %p != import %p"),
              (void*) (uintptr_t) Loaded, (void*) (uintptr_t) ExpectedLoaded);
        Ok = false;
    }

    if (FindFuncExports(NtoskrnlBase, "__kf_missing_export__") != nullptr)
    {
        print(ERROR("VerifyFindFuncExports: missing name resolved"));
        Ok = false;
    }

    const char* Wanted[3] = {
        "PsInitialSystemProcess", "__kf_missing_export__", "PsLoadedModuleList",
    };
    address Results[3] = {};
    FindFuncExportsBatch(NtoskrnlBase, Wanted, Results, 3);
    if (Results[0] != ExpectedInitial || Results[1] != nullptr ||
        Results[2] != ExpectedLoaded)
    {
        print(ERROR("VerifyFindFuncExports: batch result mismatch"));
        Ok = false;
    }

    return Ok;
}
#endif
