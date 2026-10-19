// Pattern parsing and PE image scanning: 'AA BB ??' signature strings to byte arrays, byte scans over
// image sections, and export-table walks. Pure byte/PE parsing, no kernel memory access happens here

// Hex to bytes
constexpr uint8_t HexToByte(char c) {
    return (c >= '0' && c <= '9') ? c - '0' :
           (c >= 'A' && c <= 'F') ? c - 'A' + 0xA :
           (c >= 'a' && c <= 'f') ? c - 'a' + 0xA :
           0xFF; // Invalid
}

// Pattern to Bytes. Each '?' or hex pair consumes two characters (the '?' plus the ' ' or '?'
// behind it), so single-space-separated tokens like "AA ? BB" come out one byte each
template<size_t N>
constexpr std::array<char, N> PatternToBytes(const char (&Signature)[N])
{
    std::array<char, N> Bytes{};
    size_t i = 0;
    size_t len = 0;

    while (i < N - 1)
    {
        if (Signature[i] == ' ') { ++i; continue; }
        if (Signature[i] == '?') { Bytes[len++] = '?'; i += 2; continue; }
        Bytes[len++] = static_cast<char>(HexToByte(Signature[i]) << 4 | HexToByte(Signature[i + 1]));
        i += 2;
    }

    Bytes[len] = '\0';
    return Bytes;
}

// True if the signature matches at Current ('?' matches any byte)
static bool Matches(const char *Current, const char *Signature, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (Signature[i] != '?' && Signature[i] != Current[i])
            return false;
    return true;
}

// Signature Scan
address SignatureScan(const void *StartAddress, const void *EndAddress, const char *Signature)
{
    print(INFO("Start Address: %p"), StartAddress);
    print(INFO("End Address: %p"), EndAddress);
    print(INFO("Signature Address: %p"), Signature);
    size_t size = strlen(Signature);

    // Nothing to search: a missing range, or one shorter than the signature (the bound below would wrap)
    if (!StartAddress || !EndAddress || (size_t) EndAddress - (size_t) StartAddress < size)
    {
        print(ERROR("SIGNATURE NOT FOUND!"));
        return nullptr;
    }

    for (const char *Current = (char *) StartAddress; Current <= (char *) ((size_t) EndAddress - size); ++Current)
        if (Matches(Current, Signature, size))
        {
            print(INFO("Signature: %p"), Current);
            return Current;
        }

    print(ERROR("SIGNATURE NOT FOUND!"));
    return nullptr;
}

// Section Signature Scan
address SectionScan(address BaseAddress, const char *SectionName, const char *Signature)
{
    // Get section
    auto dosHeader = (_IMAGE_DOS_HEADER *) BaseAddress;
    auto ntHeader = (_IMAGE_NT_HEADERS64 *) (BaseAddress + dosHeader->e_lfanew);
    auto fileHeader = &ntHeader->FileHeader;
    auto optionalHeader = &ntHeader->OptionalHeader;
    auto sectionHeader = (_IMAGE_SECTION_HEADER *) ((uint64_t) optionalHeader + sizeof(_IMAGE_OPTIONAL_HEADER64));
    if (!sectionHeader) return nullptr;

    // loop
    void *sectionStart{};
    void *sectionEnd{};

    // Find Section
    for (int i = 0; i < fileHeader->NumberOfSections; i++)
    {
        if (!memcmp(sectionHeader[i].Name, SectionName, strlen(SectionName)))
        {
            sectionStart = BaseAddress + sectionHeader[i].VirtualAddress;
            sectionEnd = BaseAddress + sectionHeader[i].VirtualAddress + sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    // Section not found: there is nothing to scan
    if (!sectionStart)
    {
        print(ERROR("SECTION NOT FOUND!"));
        return nullptr;
    }

    // Signature Scan
    return SignatureScan(sectionStart, sectionEnd, Signature);
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
        if (!strcmp(funcName, FuncName))
            return BaseAddress + functions[ordinals[i]];
    }

    print(ERROR("EXPORT FUNCTION NOT FOUND!"));
    return nullptr;
}
