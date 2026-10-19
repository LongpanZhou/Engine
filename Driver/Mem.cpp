enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB
};

// CR3 of the System process: maps all kernel memory and is fixed for the rest of the boot. Filled lazily
// (the value only exists after boot); every later caller reuses the runtime global
static uint64_t SystemCr3Value = 0;
cr3 GetSystemCr3()
{
    uint64_t Value = __atomic_load_n(&SystemCr3Value, __ATOMIC_SEQ_CST);
    if (!Value)
    {
        Value = ((_KPROCESS *) *__imp_PsInitialSystemProcess)->DirectoryTableBase;
        __atomic_store_n(&SystemCr3Value, Value, __ATOMIC_SEQ_CST);
    }
    return cr3{Value};
}

// Claims an empty entry (all-zero) for a mapping, atomically, so a live mapping's entry is never taken
template<typename T>
bool ClaimEntry(T *Entry, T Value)
{
    uint64_t Expected = 0;
    uint64_t Desired;
    memcpy(&Desired, &Value, sizeof(Desired));
    return __atomic_compare_exchange_n((uint64_t *) Entry, &Expected, Desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

// Empties an entry again, so the next mapping can claim it
template<typename T>
void ReleaseEntry(T *Entry)
{
    __atomic_store_n((uint64_t *) Entry, 0, __ATOMIC_SEQ_CST);
}

// The dedicated table: one 4 KB page of 512 slots in the driver image, for 4 KB mappings while linked
alignas(4096) uint64_t MapTableStorage[512];
uint64_t *MapTableEntries = nullptr;     // the slots the mapper claims; null while the table is not linked
uint64_t MapTableBase = 0;               // virtual address of slot 0 while linked
address MapTablePdEntry{};               // physical address of the page directory entry that links the table

// Maps one 4 KB page through a free slot in the dedicated table; no table search needed. False when no
// slot is free, and the caller falls back to the search
template<typename T>
bool MapInDedicatedTable(address PhysicalAddress, T &&Callback)
{
    for (uint64_t Slot = 0; Slot < 512; ++Slot)
    {
        pte *Entry = (pte *) &MapTableEntries[Slot];
        pte Value{};
        Value.present = 1;
        Value.write = 1;
        Value.execute_disable = 1;
        Value.page_frame_number = PhysicalAddress >> 12;
        if (!ClaimEntry(Entry, Value)) continue;

        Callback(address(MapTableBase + Slot * 0x1000 + PhysicalAddress.offset));
        ReleaseEntry(Entry);
        return true;
    }
    return false;
}

// Most page tables one mapping may open while searching for an empty entry (each open reads a whole table)
constexpr int MaxTablesPerMapping = 16;

// Forward declarations: the walk's table lookups go through GetVirtualAddress, whose extractor chain sits
// on the accessors defined below — the dependency cycle cannot be ordered away in the unity build
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize);

address GetVirtualAddress(address PhysicalAddress);

// AccessPhysicalMemory. On failure Value is left untouched, so a failed read is never mistaken for zero
template<typename T>
bool AccessPhysicalMemory(address PhysicalAddress, pagesize PageSize, T &Value)
{
    return MapPhysicalToVirtual(PhysicalAddress,
        [&Value](address VirtualAddress)
        {
            invlpg(VirtualAddress);
            memcpy(&Value, VirtualAddress, sizeof(T));
        },
        PageSize
        );
}

// Buffer form: copies Size bytes between pBuffer and the mapped page (read by default, write=true)
// Size must not cross the page boundary; AccessVirtualMemory guarantees that. False when unmapped
bool AccessPhysicalMemory(address PhysicalAddress, address pBuffer, size_t Size, pagesize PageSize, bool write = false)
{
    return MapPhysicalToVirtual(PhysicalAddress,
            [pBuffer, Size, write](address VirtualAddress)
            {
                invlpg(VirtualAddress);
                write ? memcpy(VirtualAddress, pBuffer, Size)
                      : memcpy(pBuffer, VirtualAddress, Size);
            },
            PageSize
    );
}

// Reads one page-table entry. Direct route first, through GetVirtualAddress (same translation the
// search below would use): plain reads instead of claimed mapping slots + invlpg. Falls back to the
// physical-mapping path when the extractors are not resolved yet or the entry is unreadable
template<typename E>
bool ReadTableEntry(address EntryPA, E &Entry)
{
    address Mapped = GetVirtualAddress(EntryPA);
    if (Mapped)
    {
        Entry = *(E *) Mapped;
        return true;
    }

    return AccessPhysicalMemory(EntryPA, Page_4KB, Entry);
}

// VA to PA walk down the page tables. False when a level is not present or a table read fails.
// PageSize: Page_4KB / Page_2MB / Page_1GB according to the entry that resolved the address
bool GetPhysicalAddress(address VirtualAddress, cr3 CR3, address &Physical, pagesize &PageSize)
{
    pml4e PML4E{};
    if (!ReadTableEntry({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8}, PML4E)) return false;
    if (!PML4E.present) return false;

    pdpe PDPTE{};
    if (!ReadTableEntry({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8}, PDPTE)) return false;
    if (!PDPTE.present) return false;
    if (((pdpe_1gb)PDPTE).page_size)
    {
        Physical = address(((pdpe_1gb)PDPTE).page_frame_number << 30 | VirtualAddress.offset_1gb());
        PageSize = Page_1GB;
        return true;
    }

    pde PDE{};
    if (!ReadTableEntry({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8}, PDE)) return false;
    if (!PDE.present) return false;
    if (((pde_2mb)PDE).page_size)
    {
        Physical = address(((pde_2mb)PDE).page_frame_number << 21 | VirtualAddress.offset_2mb());
        PageSize = Page_2MB;
        return true;
    }

    pte PT{};
    if (!ReadTableEntry({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8}, PT)) return false;
    if (!PT.present) return false;
    Physical = address(PT.page_frame_number << 12 | VirtualAddress.offset);
    PageSize = Page_4KB;
    return true;
}

// VirtualMemory, buffer form: copies Size bytes between pBuffer and VirtualAddress's address space
// (read by default, write with write=true). Returns false if a page is not present or the access failed
bool AccessVirtualMemory(address VirtualAddress, cr3 CR3, address pBuffer, size_t Size, bool write = false)
{
    // Copy one page at a time: the next virtual page can map to an unrelated physical frame
    while (Size)
    {
        size_t Chunk = 0x1000 - VirtualAddress.offset;
        if (Chunk > Size) Chunk = Size;

        address Physical{};
        pagesize PageSize{};
        if (!GetPhysicalAddress(VirtualAddress, CR3, Physical, PageSize)) return false;
        if (!AccessPhysicalMemory(Physical, pBuffer, Chunk, PageSize, write)) return false;

        VirtualAddress = address((uint64_t) VirtualAddress + Chunk);
        pBuffer = address((uint64_t) pBuffer + Chunk);
        Size -= Chunk;
    }
    return true;
}

// Copies Size bytes between two address spaces through a fixed-size stack buffer, so the kernel stack
// never depends on the Size the caller sent
bool CopyVirtualMemory(address SrcAddress, cr3 SrcCR3, address DestAddress, cr3 DestCR3, uint32_t Size)
{
    char buffer[0x400];
    while (Size)
    {
        uint32_t Chunk = Size < sizeof(buffer) ? Size : sizeof(buffer);
        if (!AccessVirtualMemory(SrcAddress, SrcCR3, (void *) buffer, Chunk, false)) return false;
        if (!AccessVirtualMemory(DestAddress, DestCR3, (void *) buffer, Chunk, true)) return false;

        SrcAddress = address((uint64_t) SrcAddress + Chunk);
        DestAddress = address((uint64_t) DestAddress + Chunk);
        Size -= Chunk;
    }
    return true;
}

// MmIsAddressValid equivalent: the walk succeeds only when every level is present
inline bool IsAddressValid(address VirtualAddress, cr3 CR3)
{
    address Physical{};
    pagesize PageSize{};
    return GetPhysicalAddress(VirtualAddress, CR3, Physical, PageSize);
}

// The table is linked through the shared kernel half of the page tables (PML4 index >= 256), so it works
// from any process context. The anchor is KUSER_SHARED_DATA's entry: fixed address, present since boot,
// fully static mappings, so its PD slot is verifiably empty (checked in VerifyMapTableAnchor below)
constexpr bool MapTableEnabled = true;
constexpr uint64_t MapTablePml4Index = 0x1EF;
constexpr uint64_t MapTablePdptIndex = 0;
constexpr uint64_t MapTablePdIndex = 0x100;

// Writes the page directory entry at the given level path so it points at TablePA, then adopts the table.
// Refused if the path is not present, the entry is not empty, or the path is a 1 GB page
bool LinkTable(cr3 CR3, address TablePA, uint64_t *TableEntries, uint64_t PML4Idx, uint64_t PDPTIdx, uint64_t PDIdx)
{
    pml4e PML4E{};
    if (!AccessPhysicalMemory({(CR3.pml4_frame_number << 12) + PML4Idx * 8}, Page_4KB, PML4E) || !PML4E.present) return false;

    pdpe PDPTE{};
    if (!AccessPhysicalMemory({(PML4E.page_frame_number << 12) + PDPTIdx * 8}, Page_4KB, PDPTE) || !PDPTE.present) return false;
    if (((pdpe_1gb)PDPTE).page_size) return false;

    uint64_t PdEntry = (PDPTE.page_frame_number << 12) + PDIdx * 8;   // physical address of the entry to write
    uint64_t Current = 0;
    if (!AccessPhysicalMemory(address(PdEntry), Page_4KB, Current) || Current != 0) return false;

    uint64_t Value = ((uint64_t) TablePA & 0x000FFFFFFFFFF000ull) | 0x3 | (1ull << 63);   // present, writable, no-execute, supervisor only
    if (!AccessPhysicalMemory(address(PdEntry), (void *) &Value, sizeof(Value), Page_4KB, true)) return false;

    MapTablePdEntry = address(PdEntry);
    MapTableBase = (PML4Idx << 39) | (PDPTIdx << 30) | (PDIdx << 21);
    if (PML4Idx >= 256) MapTableBase |= 0xFFFF000000000000ull;   // kernel addresses are sign-extended from bit 47
    MapTableEntries = TableEntries;
    return true;
}

// Debug-only: confirms the anchor region is really KUSER_SHARED_DATA before anything links: walks to
// the page and reads NtMajorVersion (10 since Windows 10). A wrong guess must not link into unknown
// memory. Release builds skip it and rely on LinkTable's own empty-entry validation
#ifdef DEBUG
bool VerifyMapTableAnchor(cr3 SystemCR3)
{
    pml4e PML4E{};
    if (!AccessPhysicalMemory({(SystemCR3.pml4_frame_number << 12) + MapTablePml4Index * 8}, Page_4KB, PML4E) || !PML4E.present) return false;
    pdpe PDPTE{};
    if (!AccessPhysicalMemory({(PML4E.page_frame_number << 12) + MapTablePdptIndex * 8}, Page_4KB, PDPTE) || !PDPTE.present || ((pdpe_1gb) PDPTE).page_size) return false;
    pde PDE{};
    if (!AccessPhysicalMemory({(PDPTE.page_frame_number << 12)}, Page_4KB, PDE) || !PDE.present || ((pde_2mb) PDE).page_size) return false;
    pte PTE4KB{};
    if (!AccessPhysicalMemory({(PDE.page_frame_number << 12)}, Page_4KB, PTE4KB) || !PTE4KB.present) return false;

    uint32_t NtMajorVersion = 0;
    if (!AccessPhysicalMemory({(PTE4KB.page_frame_number << 12) + 0x26C}, Page_4KB, NtMajorVersion) || NtMajorVersion != 10) return false;
    return true;
}
#endif

// Links the dedicated table into the shared kernel half of the page tables. The anchor entry is tried
// first; if taken, the same page directory is searched for another empty (LinkTable re-validates each candidate)
bool LinkMapTable()
{
    cr3 SystemCR3 = GetSystemCr3();
    address TablePA{};
    pagesize PageSize{};
    if (!GetPhysicalAddress(address((uint64_t) MapTableStorage), SystemCR3, TablePA, PageSize))
    {
        print(ERROR("LinkMapTable: could not translate the table storage %p"), (void *) MapTableStorage);
        return false;
    }
    print(INFO("LinkMapTable: table storage %p is at physical %p"), (void *) MapTableStorage, (void *) TablePA);

#ifdef DEBUG
    if (!VerifyMapTableAnchor(SystemCR3))
    {
        print(ERROR("LinkMapTable: the anchor region did not verify as KUSER_SHARED_DATA"));
        return false;
    }
#endif

    if (LinkTable(SystemCR3, TablePA, MapTableStorage, MapTablePml4Index, MapTablePdptIndex, MapTablePdIndex))
    {
        print(INFO("LinkMapTable: linked at PML4 %llx PDPT %llx PD %llx"), (unsigned long long) MapTablePml4Index, (unsigned long long) MapTablePdptIndex, (unsigned long long) MapTablePdIndex);
        return true;
    }

    // The configured entry is taken; search the same page directory downwards. LinkTable re-validates every
    // candidate itself, so an already-used entry just fails and the next one is tried
    for (uint64_t PdIdx = 511; ; --PdIdx)
    {
        if (LinkTable(SystemCR3, TablePA, MapTableStorage, MapTablePml4Index, MapTablePdptIndex, PdIdx))
        {
            print(INFO("LinkMapTable: configured entry was taken, linked at PML4 %llx PDPT %llx PD %llx"), (unsigned long long) MapTablePml4Index, (unsigned long long) MapTablePdptIndex, (unsigned long long) PdIdx);
            return true;
        }
        if (PdIdx == 0) break;
    }
    print(ERROR("LinkMapTable: no empty entry in the page directory"));
    return false;
}

// Unlinks the dedicated table. Other processors may still cache its translations; nothing uses them after
// this, and they are not flushed per-processor
void UnlinkMapTable()
{
    if (!MapTableEntries) return;
    uint64_t Empty = 0;
    AccessPhysicalMemory(MapTablePdEntry, (void *) &Empty, sizeof(Empty), Page_4KB, true);
    MapTableEntries = nullptr;
}

// ---------------------------------------------------------------------------
// Kernel image lookup and PTE translation. GetNtoskrnl finds ntoskrnl.exe by walking page tables; the two
// extractors pull PTE_BASE and the PfnDatabase PteAddress column out of the live image by signature; and
// GetVirtualAddress combines them into the PA -> VA translator that MapPhysicalToVirtual (defined right
// below it) uses for its table lookups
// ---------------------------------------------------------------------------

// Most pages the scan may visit before giving up: 0x4000 pages = 64 MB
constexpr uint64_t MaxScanSteps = 0x4000;

// Cached-result marker shared by GetNtoskrnl, GetPteBase and GetPfnPteAddressBase: 0 = not computed
// yet, Failed = computed and missed (a miss is deterministic per boot, so never retried). Real kernel
// pointers are >= 0xFFFF800000000000, so 1 is unambiguous
constexpr uint64_t Failed = 1;

// ntoskrnl base, found by scanning pages downwards from inside the image and cached for the boot
address GetNtoskrnl()
{
    // The base never changes while loaded; the scan costs up to 64 MB of walks, so serve it from cache
    static uint64_t CachedBase = 0;
    uint64_t Cached = __atomic_load_n(&CachedBase, __ATOMIC_SEQ_CST);
    if (Cached) return Cached == Failed ? nullptr : (address) Cached;

    // Start inside the image (the import slot of PsInitialSystemProcess lands in its data), page-aligned
    address base = (address) ((uint64_t) (void *) __imp_PsInitialSystemProcess & ~0xFFFull);

    // The scan reads image pages directly, with no IsAddressValid checks: a validity walk re-enters the
    // extractor chain while the cache is empty — unbounded recursion, kernel stack overflow, bugcheck
    // 0x7F/0x8. Direct reads are safe down to the base because every page belongs to the image

    // Brute-force scan down in 4 KB steps
    auto NtoskrnlFile = Decode(NtoskrnlName);
    uint64_t Steps = 0;     // pages visited by the scan
    uint64_t MzSeen = 0;    // pages where a valid DOS header was found
    print(INFO("GetNtoskrnl: scanning down from %p in 4 KB steps"), (void *) base);
    do {
        Steps++;

        auto dosHeader = (_IMAGE_DOS_HEADER *)base;
        if (dosHeader->e_magic != 0x5A4D)
            continue;
        MzSeen++;

        // Header-chain validation: the page being mapped does not make it a real image. Bogus e_lfanew
        // or an out-of-image export RVA turned the name pointer wild before (live bugcheck 0x50, 19041)
        if (dosHeader->e_lfanew < 0x40 || dosHeader->e_lfanew > (LONG)(0x1000 - sizeof(_IMAGE_NT_HEADERS64)))
            continue;

        auto ntHeader = (_IMAGE_NT_HEADERS64 *)(base + dosHeader->e_lfanew);
        if (ntHeader->Signature != 0x4550)
            continue;

        // ntoskrnl-class image: at least one page, at most the whole 64 MB scan window
        uint32_t SizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
        if (SizeOfImage < 0x1000 || SizeOfImage > MaxScanSteps * 0x1000)
            continue;

        auto dataDir = ntHeader->OptionalHeader.DataDirectory;
        if (dataDir->VirtualAddress == 0 || dataDir->VirtualAddress >= SizeOfImage)
            continue;

        auto exportDir = (_IMAGE_EXPORT_DIRECTORY *)(base + dataDir->VirtualAddress);
        if (exportDir->Name >= SizeOfImage)
            continue;

        const char* name = (const char*)(base + exportDir->Name);
        if (strcmp(name, NtoskrnlFile.data()))
            continue;

        // Match: cache and return
        __atomic_store_n(&CachedBase, (uint64_t) base, __ATOMIC_SEQ_CST);
        print(INFO("GetNtoskrnl: found ntoskrnl.exe at %p after %llu steps"), (void *) base, Steps);
        return base;
    } while (Steps < MaxScanSteps && (base -= 0x1000));

    print(ERROR("GetNtoskrnl: NOT FOUND after %llu steps, %llu valid DOS headers"), Steps, MzSeen);
    __atomic_store_n(&CachedBase, Failed, __ATOMIC_SEQ_CST);
    return nullptr;
}

// Shared body of the two extractors below: scans PAGE then .text of ntoskrnl for the instruction
// signature, verifies the shl displacement byte at Match + GuardOffset, and reads the imm64 at
// Match + 2 (must be a canonical kernel pointer). The caller does the caching
template<size_t N>
static address ExtractImm64(const std::array<char, N> &Pattern, uint32_t GuardOffset, const char *What)
{
    address Base = GetNtoskrnl();
    if (!Base) return nullptr;

    // The pattern can live in PAGE or .text depending on build; the shared helper tries both
    address Match = ScanModuleImage(Base, Pattern.data());
    if (!Match) return nullptr;
    print(INFO("%s: instruction at %p matches"), What, (void *) Match);

    if (*(uint8_t *) (Match + GuardOffset) != 0x19)
    {
        print(WARN("%s: match at %p is not followed by a shl, discarding"), What, (void *) Match);
        return nullptr;
    }

    uint64_t Value = *(uint64_t *) (Match + 2);
    if ((Value >> 48) != 0xFFFF) // canonical kernel pointers have the top 16 bits all set
    {
        print(WARN("%s: extracted value %p is not a kernel pointer"), What, (void *) Value);
        return nullptr;
    }

    print(OK("%s: extracted %p, instruction at %p"), What, (void *) Value, (void *) Match);
    return (address) Value;
}

// PTE_BASE, the base of the page-table self-map the kernel uses for MiGetPteAddress. Not exported; on this
// layout MmGetVirtualForPhysical holds it as the plain imm64 of
//     mov rdx, <PTE_BASE>
//     shl rdx, 19h
// Kernel constant plus a megabytes-scale scan: read once, then cache (same pattern as GetNtoskrnl)
address GetPteBase()
{
    static uint64_t CachedBase = 0;
    uint64_t Cached = __atomic_load_n(&CachedBase, __ATOMIC_SEQ_CST);
    if (Cached) return (address) Cached;

    address PteBase = ExtractImm64(Decode(PteBaseSignature), 13, "GetPteBase");
    __atomic_store_n(&CachedBase, PteBase ? (uint64_t) PteBase : Failed, __ATOMIC_SEQ_CST);
    return PteBase;
}

// Base of the PfnDatabase PteAddress column, extracted the same way as GetPteBase. The imm64 is the address of
// entry 0's PteAddress field, so the PteAddress of PFN n is at Base + n * 0x30 (the function's rdx = PFN * 6, scaled
// by 8 in the [rax+rdx*8] load). Read once, then cached
address GetPfnPteAddressBase()
{
    static uint64_t CachedBase = 0;
    uint64_t Cached = __atomic_load_n(&CachedBase, __ATOMIC_SEQ_CST);
    if (Cached) return (address) Cached;

    address PfnPteAddressBase = ExtractImm64(Decode(PfnPteAddressSignature), 17, "GetPfnPteAddressBase");
    __atomic_store_n(&CachedBase, PfnPteAddressBase ? (uint64_t) PfnPteAddressBase : Failed, __ATOMIC_SEQ_CST);
    return PfnPteAddressBase;
}

// PA -> VA through the self-map: read PfnDatabase[PA >> 12].PteAddress, then the PTE's index in the
// self-map gives the VA (sign-extended from bit 47), plus the page offset. Null when a table is
// missing/unreadable or the PteAddress is outside the self-map
address GetVirtualAddress(address PhysicalAddress)
{
    uint64_t PteBase = (uint64_t) GetPteBase();
    uint64_t PfnPteAddressBase = (uint64_t) GetPfnPteAddressBase();
    if (!PteBase || !PfnPteAddressBase) return nullptr;

    uint64_t Pa = (uint64_t) PhysicalAddress;
    uint64_t Entry = PfnPteAddressBase + (Pa >> 12) * 0x30;

    // The PfnDatabase entry is read directly: this function's own translations are on the validity-walk
    // path, so a check would recurse. The base itself is pinned by ExtractImm64's shl guard + canonical check
    uint64_t PteAddress = *(uint64_t *) Entry;
    if (!PteAddress) return nullptr;

    // The PTE must lie inside the self-map, which is 512 GB (2^39 bytes) of 8-byte entries; the subtraction wraps for
    // anything below PTE_BASE, so the unsigned compare rejects both sides
    uint64_t Offset = PteAddress - PteBase;
    if (Offset >= (1ULL << 39)) return nullptr;

    uint64_t Va = (Offset << 9);
    Va = (uint64_t) ((int64_t) (Va << 16) >> 16); // canonical form: sign-extend from bit 47
    return (address) (Va + (Pa & 0xFFF));
}

// MapPhysicalToVirtual: scans the page tables for an empty entry at any level (a full table is
// skipped), giving up after MaxTablesPerMapping opens. A dedicated-table hit short-circuits the search
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize)
{
    // While the dedicated table is linked, a 4 KB mapping takes a slot in it. If it has no free slot, the search below runs
    if (PageSize == Page_4KB && MapTableEntries && MapInDedicatedTable(PhysicalAddress, Callback)) return true;

    // Per-call state, so concurrent mappings never share anything
    int Opened = 0;
    cr3 CR3 = read_cr3();
    address VA{};

    // PML4: every present entry leads to a PDPT. A null translation (extractors not resolvable)
    // aborts the search instead of dereferencing a null table
    address PML4Table = GetVirtualAddress({CR3.pml4_frame_number << 12});
    if (!PML4Table) return false;
    for (int PML4_IDX = 0; PML4_IDX < 512; ++PML4_IDX)
    {
        pml4e *PML4E = &((pml4e *) PML4Table)[PML4_IDX];
        if (!PML4E->present) continue;
        if (++Opened > MaxTablesPerMapping) return false;

        // PDPT
        address PDPTTable = GetVirtualAddress({PML4E->page_frame_number << 12});
        if (!PDPTTable) return false;
        for (int PDPT_IDX = 0; PDPT_IDX < 512; ++PDPT_IDX)
        {
            pdpe *PDPTE = &((pdpe *) PDPTTable)[PDPT_IDX];
            if (PageSize == Page_1GB)
            {
                if (PDPTE->present) continue;

                pdpe_1gb Value{};
                Value.present = 1;
                Value.write = 1;
                Value.execute_disable = 1;
                Value.page_size = 1;
                Value.page_frame_number = PhysicalAddress >> 30;
                if (!ClaimEntry((pdpe_1gb *) PDPTE, Value)) continue;

                VA.offset = PhysicalAddress.offset;
                VA.p1_index = PhysicalAddress.p1_index;
                VA.p2_index = PhysicalAddress.p2_index;
                VA.p3_index = PDPT_IDX;
                VA.p4_index = PML4_IDX;

                Callback(VA);
                ReleaseEntry((pdpe_1gb *) PDPTE);
                return true;
            }

            // A 1GB entry maps memory directly and is not a table, so only a present, non-large entry leads to a PD
            if (!PDPTE->present || ((pdpe_1gb *) PDPTE)->page_size) continue;
            if (++Opened > MaxTablesPerMapping) return false;

            // PD
            address PDTable = GetVirtualAddress({PDPTE->page_frame_number << 12});
            if (!PDTable) return false;
            for (int PD_IDX = 0; PD_IDX < 512; ++PD_IDX)
            {
                pde *PDE = &((pde *) PDTable)[PD_IDX];
                if (PageSize == Page_2MB)
                {
                    if (PDE->present) continue;

                    pde_2mb Value{};
                    Value.present = 1;
                    Value.write = 1;
                    Value.execute_disable = 1;
                    Value.page_size = 1;
                    Value.page_frame_number = PhysicalAddress >> 21;
                    if (!ClaimEntry((pde_2mb *) PDE, Value)) continue;

                    VA.offset = PhysicalAddress.offset;
                    VA.p1_index = PhysicalAddress.p1_index;
                    VA.p2_index = PD_IDX;
                    VA.p3_index = PDPT_IDX;
                    VA.p4_index = PML4_IDX;

                    Callback(VA);
                    ReleaseEntry((pde_2mb *) PDE);
                    return true;
                }

                // Same rule as the PDPT: a 2MB entry is a mapping, not a page table
                if (!PDE->present || ((pde_2mb *) PDE)->page_size) continue;
                if (++Opened > MaxTablesPerMapping) return false;

                // PT
                address PTTable = GetVirtualAddress({PDE->page_frame_number << 12});
                if (!PTTable) return false;
                for (int PT_IDX = 0; PT_IDX < 512; ++PT_IDX)
                {
                    pte *PTE_4KB = &((pte *) PTTable)[PT_IDX];
                    if (PTE_4KB->present) continue;

                    pte Value{};
                    Value.present = 1;
                    Value.write = 1;
                    Value.execute_disable = 1;
                    Value.page_frame_number = PhysicalAddress >> 12;
                    if (!ClaimEntry(PTE_4KB, Value)) continue;

                    VA.offset = PhysicalAddress.offset;
                    VA.p1_index = PT_IDX;
                    VA.p2_index = PD_IDX;
                    VA.p3_index = PDPT_IDX;
                    VA.p4_index = PML4_IDX;

                    Callback(VA);
                    ReleaseEntry(PTE_4KB);
                    return true;
                }
            }
        }
    }

    return false;
}

// Verifies the PTE_BASE extracted by GetPteBase() against the kernel itself: the exported MM routines
// are ground truth, and the self-map walk must agree with them on each sample
static bool SelfMapAgrees(address PteBase, address Va, address Physical, cr3 Cr3)
{
    const uint64_t Mask = (1ULL << 39) - 8;
    uint64_t PteSlot = (uint64_t) PteBase + (((uint64_t) Va >> 9) & Mask);
    uint64_t PdeSlot = (uint64_t) PteBase + ((PteSlot >> 9) & Mask);

    if (!IsAddressValid((address) PdeSlot, Cr3)) return false;
    uint64_t Pde = *(uint64_t *) PdeSlot;
    if (!(Pde & 1)) return false;

    // Large page: frame in bits 21..51, the low 21 bits of the VA are the offset inside the 2 MB page
    if (Pde & (1ULL << 7))
        return (Pde & 0x000FFFFFFFE00000ULL) + ((uint64_t) Va & 0x1FFFFF) == (uint64_t) Physical;

    // 4 KB page: present in bit 0, frame number in bits 12..51
    if (!IsAddressValid((address) PteSlot, Cr3)) return false;
    uint64_t Pte = *(uint64_t *) PteSlot;
    return (Pte & 1) && ((Pte >> 12) & 0xFFFFFFFFFF) == ((uint64_t) Physical >> 12);
}

// Verifies GetPteBase() silently: for each sample (the driver's own code page, ntoskrnl+0x1000) the exported MM
// routines give a ground-truth physical page and the self-map walk must agree with it. False on any mismatch
bool VerifyPteBase()
{
    auto PteBase = GetPteBase();
    if (!PteBase) return false;

    const cr3 SystemCR3 = GetSystemCr3();
    address Nt = GetNtoskrnl();
    const address Samples[2] = {address((uint64_t) &VerifyPteBase), Nt ? Nt + 0x1000 : address{}};

    for (address Sample : Samples)
    {
        if (!Sample) continue;

        address Physical = win::MmGetPhysicalAddress(Sample);
        if (!SelfMapAgrees(PteBase, Sample, Physical, SystemCR3)) return false;

        // MmGetVirtualForPhysical may return the sample itself, in which case there is nothing new to test
        address MmSaid = win::MmGetVirtualForPhysical(Physical);
        if (MmSaid && (uint64_t) MmSaid != (uint64_t) Sample &&
            !SelfMapAgrees(PteBase, MmSaid, Physical, SystemCR3))
            return false;

        // Our implementation must return exactly what the kernel returns for the same physical address
        if (MmSaid && (uint64_t) GetVirtualAddress(Physical) != (uint64_t) MmSaid) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Memory self-test. The vendor headers declare the kernel's own MM routines (win::MmGetPhysicalAddress,
// win::MmGetVirtualForPhysical, win::MmIsAddressValid), so their answers are ground truth for every
// step the driver does by hand. Debug builds only: release builds never call VerifyMemory, --gc-sections
// drops it, and no import table entries are created
// ---------------------------------------------------------------------------

// One kernel address through the whole stack: VA->PA (GetPhysicalAddress vs MmGetPhysicalAddress),
// PA->VA (GetVirtualAddress vs MmGetVirtualForPhysical), validity (IsAddressValid vs MmIsAddressValid)
// and the read path (AccessVirtualMemory and AccessPhysicalMemory vs a direct read; kernel memory is
// directly readable at DriverEntry's IRQL). Returns the number of failed checks
static uint32_t VerifyOneAddress(address Va, cr3 SystemCR3, const char *What)
{
    uint32_t Failures = 0;

    // VA -> PA, our walk against the kernel's
    address Physical{};
    pagesize PageSize{};
    if (!GetPhysicalAddress(Va, SystemCR3, Physical, PageSize))
    {
        print(ERROR("VerifyMemory: %s %p: GetPhysicalAddress failed"), What, (void *) Va);
        return 1;
    }

    address MmPhysical = win::MmGetPhysicalAddress(Va);
    if ((uint64_t) Physical != (uint64_t) MmPhysical)
    {
        print(ERROR("VerifyMemory: %s %p: VA->PA ours %p, MM %p"), What, (void *) Va,
              (void *) Physical, (void *) MmPhysical);
        Failures++;
    }

    // PA -> VA, our translator against the kernel's
    address MmVirtual = win::MmGetVirtualForPhysical(MmPhysical);
    if (MmVirtual && (uint64_t) GetVirtualAddress(MmPhysical) != (uint64_t) MmVirtual)
    {
        print(ERROR("VerifyMemory: %s %p: PA->VA ours %p, MM %p"), What, (void *) Va,
              (void *) GetVirtualAddress(MmPhysical), (void *) MmVirtual);
        Failures++;
    }

    // Validity, our walk against the kernel's
    if (IsAddressValid(Va, SystemCR3) != win::MmIsAddressValid(Va))
    {
        print(ERROR("VerifyMemory: %s %p: IsAddressValid disagrees with MmIsAddressValid"), What, (void *) Va);
        Failures++;
    }

    // Read path: the rest of the page (capped at 32 bytes, so the physical read stays inside one
    // mapping) read directly, through the virtual accessor, and through the physical mapper
    size_t Bytes = 0x1000 - Va.offset;
    if (Bytes > 32) Bytes = 32;

    uint8_t Direct[32];
    memcpy(Direct, (void *) (uint64_t) Va, Bytes);

    uint8_t ViaVirtual[32] = {};
    if (!AccessVirtualMemory(Va, SystemCR3, (void *) ViaVirtual, Bytes) ||
        memcmp(Direct, ViaVirtual, Bytes))
    {
        print(ERROR("VerifyMemory: %s %p: AccessVirtualMemory read mismatch"), What, (void *) Va);
        Failures++;
    }

    uint8_t ViaPhysical[32] = {};
    if (!AccessPhysicalMemory(MmPhysical, (void *) ViaPhysical, Bytes, PageSize) ||
        memcmp(Direct, ViaPhysical, Bytes))
    {
        print(ERROR("VerifyMemory: %s %p: AccessPhysicalMemory read mismatch"), What, (void *) Va);
        Failures++;
    }

    return Failures;
}

// Write path on stack memory, so no kernel or image data is touched: a pattern goes in through the
// physical mapper and through CopyVirtualMemory (the same path the command hook uses) and comes back
// out through a direct read both times. Returns the number of failed checks
static uint32_t VerifyWritePath(cr3 SystemCR3)
{
    uint8_t Expected[64];
    uint8_t Zeros[64] = {};
    uint8_t Scratch[64];
    for (size_t i = 0; i < sizeof(Expected); ++i)
        Expected[i] = (uint8_t) (i * 7 + 1);
    memcpy(Scratch, Zeros, sizeof(Scratch));

    // Capped to the rest of the page, so the physical write stays inside one mapping
    address Va = address((uint64_t) (void *) Scratch);
    size_t Bytes = 0x1000 - Va.offset;
    if (Bytes > sizeof(Scratch)) Bytes = sizeof(Scratch);

    address Physical{};
    pagesize PageSize{};
    if (!GetPhysicalAddress(Va, SystemCR3, Physical, PageSize))
    {
        print(ERROR("VerifyMemory: write path: GetPhysicalAddress failed for %p"), (void *) Va);
        return 1;
    }

    uint32_t Failures = 0;

    // Physical write: the pattern goes in through the mapper, comes back out through a direct read
    if (!AccessPhysicalMemory(Physical, (void *) Expected, Bytes, PageSize, true) ||
        memcmp(Scratch, Expected, Bytes))
    {
        print(ERROR("VerifyMemory: AccessPhysicalMemory write mismatch"));
        Failures++;
    }

    memcpy(Scratch, Zeros, sizeof(Scratch));

    // CopyVirtualMemory, the same path the NtCompareSigningLevels commands take (same address space
    // here; the hook's cross-process case is the same code with a second CR3). It chunks across
    // pages itself, so the full 64 bytes can go in one call
    address Src = address((uint64_t) (void *) Expected);
    if (!CopyVirtualMemory(Src, SystemCR3, Va, SystemCR3, sizeof(Expected)) ||
        memcmp(Scratch, Expected, sizeof(Expected)))
    {
        print(ERROR("VerifyMemory: CopyVirtualMemory mismatch"));
        Failures++;
    }

    return Failures;
}

// Runs the memory self-test: code, data, stack and kernel-image samples through VerifyOneAddress, the
// write path through VerifyWritePath, and an unmapped-address agreement check. True when every check
// passed. Debug builds only (see the section banner above)
bool VerifyMemory()
{
    const cr3 SystemCR3 = GetSystemCr3();
    uint32_t Failures = 0;

    // Samples: the driver's own code and data, a stack local, and ntoskrnl's first page
    address Nt = GetNtoskrnl();
    uint64_t StackLocal = 0;
    const address Samples[] = {
        address((uint64_t) &VerifyOneAddress),             // driver code
        address((uint64_t) (void *) MapTableStorage),     // driver data
        address((uint64_t) &StackLocal),                   // kernel stack
        Nt ? Nt + 0x1000 : address{},                      // kernel image
    };
    const char * const Names[] = {"driver code", "driver data", "kernel stack", "kernel image"};
    static_assert(sizeof(Samples) / sizeof(Samples[0]) == sizeof(Names) / sizeof(Names[0]));

    for (size_t i = 0; i < sizeof(Samples) / sizeof(Samples[0]); ++i)
    {
        if (!Samples[i]) continue;
        print(INFO("VerifyMemory: sample %s at %p"), Names[i], (void *) Samples[i]);
        Failures += VerifyOneAddress(Samples[i], SystemCR3, Names[i]);
    }

    // An address nothing maps (low user half of the System process): both sides must call it invalid
    if (IsAddressValid(address(0x1000), SystemCR3) != win::MmIsAddressValid(address(0x1000)))
    {
        print(ERROR("VerifyMemory: IsAddressValid disagrees with MmIsAddressValid on an unmapped address"));
        Failures++;
    }

    Failures += VerifyWritePath(SystemCR3);

    if (Failures) print(ERROR("VerifyMemory: %u check(s) FAILED"), Failures);
    else print(OK("VerifyMemory: all checks passed (VA->PA, PA->VA, validity, virtual/physical read, physical write, copy)"));
    return Failures == 0;
}
