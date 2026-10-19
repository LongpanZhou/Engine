enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB,
    Page_Unmap
};

// CR3 of the System process: maps all kernel memory and is fixed for the rest of the boot, so every page-table
// walker (here and in the extractors below) reads the same runtime global. It cannot be compile-initialized (the value only
// exists once the kernel has booted), so the first GetSystemCr3() call fills it and every later caller reuses it
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

// Claims an empty entry for a mapping. An entry is empty only when all of its bits are zero, so a claim never
// takes an entry that a live mapping still uses, or overwrites a non-present entry that holds other state
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

// The dedicated table: one 4 KB page of 512 slots that only the driver uses for 4 KB mappings. Its storage is in the
// driver image. While it is linked (MapTableEntries is set), a mapping claims a slot in it instead of searching the tables
alignas(4096) uint64_t MapTableStorage[512];
uint64_t *MapTableEntries = nullptr;     // the slots the mapper claims; null while the table is not linked
uint64_t MapTableBase = 0;               // virtual address of slot 0 while linked
address MapTablePdEntry{};               // physical address of the page directory entry that links the table

// Maps one 4 KB page through a free slot in the dedicated table. The slot's address is known, so no tables are searched.
// Returns false if the table has no free slot; the caller then searches as usual
template<typename T>
bool MapInDedicatedTable(address PhysicalAddress, T &&Callback)
{
    for (uint64_t Slot = 0; Slot < 512; ++Slot)
    {
        pte *Entry = (pte *) &MapTableEntries[Slot];
        pte Value{};
        Value.present = 1;
        Value.write = 1;
        Value.page_frame_number = PhysicalAddress >> 12;
        if (!ClaimEntry(Entry, Value)) continue;

        Callback(address(MapTableBase + Slot * 0x1000 + PhysicalAddress.offset));
        ReleaseEntry(Entry);
        return true;
    }
    return false;
}

// The most page tables one mapping may open while it searches for an empty entry. Each open reads a whole table, so
// this bounds the work one mapping can do
constexpr int MaxTablesPerMapping = 16;

// Declared here because the two AccessPhysicalMemory overloads below call it, and defined after GetVirtualAddress
// further down: the walk's table lookups go through GetVirtualAddress, whose extractor chain (GetNtoskrnl,
// GetPteBase, ...) sits on those accessors, so the cycle cannot be ordered away
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize);

// PhysicalMemory. Returns false when no mapping could be made, and then Value is left untouched, so a failed read is
// never mistaken for zero
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

// Size must not cross the page the mapping covers; AccessVirtualMemory guarantees that
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

// Translate Virtual Address to Physical Address. Returns false if the page is not present, or if a table could not be
// read because no mapping slot was free. Translation...       Type 0: 4KB, Type 1: 2MB, Type 2: 1GB
bool GetPhysicalAddress(address VirtualAddress, cr3 CR3, address &Physical, pagesize &PageSize)
{
    pml4e PML4E{};
    if (!AccessPhysicalMemory({(CR3.pml4_frame_number << 12) + VirtualAddress.p4_index * 8}, Page_4KB, PML4E)) return false;
    if (!PML4E.present) return false;

    pdpe PDPTE{};
    if (!AccessPhysicalMemory({(PML4E.page_frame_number << 12) + VirtualAddress.p3_index * 8}, Page_4KB, PDPTE)) return false;
    if (!PDPTE.present) return false;
    if (((pdpe_1gb)PDPTE).page_size)
    {
        Physical = address(((pdpe_1gb)PDPTE).page_frame_number << 30 | VirtualAddress.offset_1gb());
        PageSize = Page_1GB;
        return true;
    }

    pde PDE{};
    if (!AccessPhysicalMemory({(PDPTE.page_frame_number << 12) + VirtualAddress.p2_index * 8}, Page_4KB, PDE)) return false;
    if (!PDE.present) return false;
    if (((pde_2mb)PDE).page_size)
    {
        Physical = address(((pde_2mb)PDE).page_frame_number << 21 | VirtualAddress.offset_2mb());
        PageSize = Page_2MB;
        return true;
    }

    pte PT{};
    if (!AccessPhysicalMemory({(PDE.page_frame_number << 12) + VirtualAddress.p1_index * 8}, Page_4KB, PT)) return false;
    if (!PT.present) return false;
    Physical = address(PT.page_frame_number << 12 | VirtualAddress.offset);
    PageSize = Page_4KB;
    return true;
}

// VirtualMemory. Returns false if the page is not present or the read failed; Value is left untouched in that case
template<typename T>
bool AccessVirtualMemory(address VirtualAddress, cr3 CR3, T &Value)
{
    address Physical{};
    pagesize PageSize{};
    if (!GetPhysicalAddress(VirtualAddress, CR3, Physical, PageSize)) return false;
    return AccessPhysicalMemory(Physical, PageSize, Value);
}

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

// MmIsAddressValid
inline bool IsAddressValid(address VirtualAddress, cr3 CR3)
{
    address Physical{};
    pagesize PageSize{};
    return GetPhysicalAddress(VirtualAddress, CR3, Physical, PageSize);
}

// The link is off by default. It changes kernel page tables, so the placeholder entry below must be checked on the
// Windows VM (it has to be empty, and shared by every process) before this is turned on
constexpr bool MapTableEnabled = true;
constexpr uint64_t MapTablePml4Index = 2;
constexpr uint64_t MapTablePdptIndex = 0;
constexpr uint64_t MapTablePdIndex = 2;

// Writes the page directory entry at (PML4Idx, PDPTIdx, PDIdx) under CR3, so it points at the table at TablePA, and starts
// using the table at TableEntries. Refused if the path is not present, the entry is not empty, or the path is a 1 GB page
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

    uint64_t Value = ((uint64_t) TablePA & 0x000FFFFFFFFFF000ull) | 0x3;   // present and writable, supervisor only
    if (!AccessPhysicalMemory(address(PdEntry), (void *) &Value, sizeof(Value), Page_4KB, true)) return false;

    MapTablePdEntry = address(PdEntry);
    MapTableBase = (PML4Idx << 39) | (PDPTIdx << 30) | (PDIdx << 21);
    if (PML4Idx >= 256) MapTableBase |= 0xFFFF000000000000ull;   // kernel addresses are sign-extended from bit 47
    MapTableEntries = TableEntries;
    return true;
}

// Links the dedicated table into the System process's tables at the configured entry
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
    bool Linked = LinkTable(SystemCR3, TablePA, MapTableStorage, MapTablePml4Index, MapTablePdptIndex, MapTablePdIndex);
    print(INFO("LinkMapTable: LinkTable returned %u"), (uint32_t) Linked);
    return Linked;
}

// Clears the link and stops using the dedicated table, so later mappings search the tables as before. Other processors
// may still cache translations of the table's addresses. Nothing uses them after this, but they are not flushed on each processor
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

// Most pages the scan may visit before giving up: 0x4000 pages = 64 MB, far more than the ntoskrnl image spans
constexpr uint64_t MaxScanSteps = 0x4000;

// Get ntoskrnl.exe address
address GetNtoskrnl()
{
    // The base never changes while the driver is loaded, but the scan below costs up to 64 MB of page-table
    // walks and every ResolveKernelSymbol call repeats it. Scan once, then serve the cached result
    static uint64_t CachedBase = 0;
    uint64_t Cached = __atomic_load_n(&CachedBase, __ATOMIC_SEQ_CST);
    if (Cached) return (address) Cached;

    // Start inside ntoskrnl, not at the IDT base: the IDT is not always inside the image (it was below it on one boot).
    // __imp_PsInitialSystemProcess is the loader's import slot for a variable in ntoskrnl's data, so its address is
    // inside the image. Round it down to a page boundary so the 4 KB steps land on page headers
    address base = (address) ((uint64_t) (void *) __imp_PsInitialSystemProcess & ~0xFFFull);

    // The scan reads the image pages DIRECTLY, with no IsAddressValid checks: a validity walk goes through
    // MapPhysicalToVirtual and GetVirtualAddress, whose extractor chain calls back into this scan while the
    // cache is still empty (unbounded recursion, kernel stack overflow, bugcheck 0x7F/8). Direct reads are
    // safe: the start is inside the image, every page down to its base belongs to it (permanently mapped,
    // a paged-out one pages back in at PASSIVE_LEVEL), and the name check stops the scan at the base

    // Brute Force
    auto NtoskrnlFile = Decode(NtoskrnlName);
    uint64_t Steps = 0;     // pages visited by the scan
    uint64_t MzSeen = 0;    // pages where a valid DOS header was found
    print(INFO("GetNtoskrnl: scanning down from %p in 4 KB steps"), (void *) base);
    do {
        Steps++;

        // Get Data Directory
        auto dosHeader = (_IMAGE_DOS_HEADER *)base;
        if (dosHeader->e_magic != 0x5A4D)
            continue;
        MzSeen++;

        // Header-chain validation: the scan only guarantees the page is mapped, not that it is a real
        // image. Pages inside ntoskrnl's own data can start with "MZ" by coincidence, and a bogus
        // e_lfanew / export RVA then turns the name pointer into a wild address (live bugcheck 0x50
        // in strcmp, caught on 19041 with name = base + garbage 0xC5B0800). Real headers always
        // sit in the image's first page, and every RVA must stay inside the declared image size
        if (dosHeader->e_lfanew < 0x40 || dosHeader->e_lfanew > 0x1000 - sizeof(_IMAGE_NT_HEADERS64))
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

        // Get module name from export directory
        const char* name = (const char*)(base + exportDir->Name);

        // Check ntoskrnl.exe
        if (strcmp(name, NtoskrnlFile.data()))
            continue;

        // Ntoskrnl.exe
        __atomic_store_n(&CachedBase, (uint64_t) base, __ATOMIC_SEQ_CST);
        print(INFO("GetNtoskrnl: found ntoskrnl.exe at %p after %llu steps"), (void *) base, Steps);
        return base;
    } while (Steps < MaxScanSteps && (base -= 0x1000));

    print(ERROR("GetNtoskrnl: NOT FOUND after %llu steps, %llu valid DOS headers"), Steps, MzSeen);
    return nullptr;
}

// Shared body of the two extractors below: scans PAGE then .text of ntoskrnl for Pattern (an
// instruction-shaped signature), verifies the shl displacement byte at Match + GuardOffset (a stray
// mov imm64 cannot match), then reads the imm64 at Match + 2 and checks it is a canonical kernel
// pointer. Returns nullptr on any miss; the caller does the caching
template<size_t N>
static address ExtractImm64(const std::array<char, N> &Pattern, uint32_t GuardOffset, const char *What)
{
    address Base = GetNtoskrnl();
    if (!Base) return nullptr;

    // The pattern can live in PAGE or .text depending on build; try both
    address Match = SectionScan(Base, Decode(PageSectionName).data(), Pattern.data());
    if (!Match) Match = SectionScan(Base, Decode(TextSectionName).data(), Pattern.data());
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
    if (!PteBase) return nullptr;

    __atomic_store_n(&CachedBase, (uint64_t) PteBase, __ATOMIC_SEQ_CST);
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
    if (!PfnPteAddressBase) return nullptr;

    __atomic_store_n(&CachedBase, (uint64_t) PfnPteAddressBase, __ATOMIC_SEQ_CST);
    return PfnPteAddressBase;
}

// Our own GetVirtualAddress, the same steps as the kernel routine with both tables taken from signatures:
//   1. PFN = PA >> 12; PteAddress = PfnDatabase[PFN].PteAddress
//   2. VA of that PTE = sign-extend48((PteAddress - PTE_BASE) << 9), which is MiGetVirtualAddressMappedByPte
//      (PTE_BASE is the self-map: idx * 8 bytes of PTEs map idx * 4 KB, and << 9 turns idx * 8 into idx * 4096)
//   3. Add the byte offset of PA inside its page
// Returns nullptr when a table cannot be found, the PFN entry is not readable, or the PteAddress is outside the self-map
address GetVirtualAddress(address PhysicalAddress)
{
    uint64_t PteBase = (uint64_t) GetPteBase();
    uint64_t PfnPteAddressBase = (uint64_t) GetPfnPteAddressBase();
    if (!PteBase || !PfnPteAddressBase) return nullptr;

    uint64_t Pa = (uint64_t) PhysicalAddress;
    uint64_t Entry = PfnPteAddressBase + (Pa >> 12) * 0x30;

    // The PfnDatabase entry is read directly: it sits in permanently-mapped system space, and the
    // extracted base is already pinned by the shl guard and the canonical-pointer check in ExtractImm64.
    // A validity walk here would recurse (IsAddressValid -> MapPhysicalToVirtual -> back into this
    // function) with no base case, because the walk itself needs this function's translations
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

// MapPhysicalToVirtual. The search tries every present entry at each level, so a full table is skipped and the next
// one is tried. It gives up after MaxTablesPerMapping tables (declared above, next to the accessors that call it)
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize)
{
    // While the dedicated table is linked, a 4 KB mapping takes a slot in it. If it has no free slot, the search below runs
    if (PageSize == Page_4KB && MapTableEntries && MapInDedicatedTable(PhysicalAddress, Callback)) return true;

    // Local variables. They are per call, so concurrent callers never share mapping state
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

// Verifies the PTE_BASE extracted by GetPteBase() against the kernel itself. No user-mode API can hand out
// PTE_BASE (kernel memory is invisible to user mode), but ntoskrnl exports the two MM routines that answer
// the same question (win::MmGetPhysicalAddress / win::MmGetVirtualForPhysical, declared by the vendor
// headers). For a virtual address of ours, win::MmGetPhysicalAddress gives the real physical page as ground
// truth: the self-map translation of Va must come out as Physical. The PDE is read first: when its PS bit is
// set the VA is covered by a 2 MB large page that has no PTE page, so the frame comes from the PDE instead
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
    uint32_t Failed = 0;

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
        Failed++;
    }

    // PA -> VA, our translator against the kernel's
    address MmVirtual = win::MmGetVirtualForPhysical(MmPhysical);
    if (MmVirtual && (uint64_t) GetVirtualAddress(MmPhysical) != (uint64_t) MmVirtual)
    {
        print(ERROR("VerifyMemory: %s %p: PA->VA ours %p, MM %p"), What, (void *) Va,
              (void *) GetVirtualAddress(MmPhysical), (void *) MmVirtual);
        Failed++;
    }

    // Validity, our walk against the kernel's
    if (IsAddressValid(Va, SystemCR3) != win::MmIsAddressValid(Va))
    {
        print(ERROR("VerifyMemory: %s %p: IsAddressValid disagrees with MmIsAddressValid"), What, (void *) Va);
        Failed++;
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
        Failed++;
    }

    uint8_t ViaPhysical[32] = {};
    if (!AccessPhysicalMemory(MmPhysical, (void *) ViaPhysical, Bytes, PageSize) ||
        memcmp(Direct, ViaPhysical, Bytes))
    {
        print(ERROR("VerifyMemory: %s %p: AccessPhysicalMemory read mismatch"), What, (void *) Va);
        Failed++;
    }

    return Failed;
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

    uint32_t Failed = 0;

    // Physical write: the pattern goes in through the mapper, comes back out through a direct read
    if (!AccessPhysicalMemory(Physical, (void *) Expected, Bytes, PageSize, true) ||
        memcmp(Scratch, Expected, Bytes))
    {
        print(ERROR("VerifyMemory: AccessPhysicalMemory write mismatch"));
        Failed++;
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
        Failed++;
    }

    return Failed;
}

// Runs the memory self-test: code, data, stack and kernel-image samples through VerifyOneAddress, the
// write path through VerifyWritePath, and an unmapped-address agreement check. True when every check
// passed. Debug builds only (see the section banner above)
bool VerifyMemory()
{
    const cr3 SystemCR3 = GetSystemCr3();
    uint32_t Failed = 0;

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
        Failed += VerifyOneAddress(Samples[i], SystemCR3, Names[i]);
    }

    // An address nothing maps (low user half of the System process): both sides must call it invalid
    if (IsAddressValid(address(0x1000), SystemCR3) != win::MmIsAddressValid(address(0x1000)))
    {
        print(ERROR("VerifyMemory: IsAddressValid disagrees with MmIsAddressValid on an unmapped address"));
        Failed++;
    }

    Failed += VerifyWritePath(SystemCR3);

    if (Failed) print(ERROR("VerifyMemory: %u check(s) FAILED"), Failed);
    else print(OK("VerifyMemory: all checks passed (VA->PA, PA->VA, validity, virtual/physical read, physical write, copy)"));
    return Failed == 0;
}
