using namespace arch;
using namespace intrin;

enum pagesize : uint32_t
{
    Page_4KB,
    Page_2MB,
    Page_1GB,
    Page_Unmap
};

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

// MapPhysicalToVirtual. The search tries every present entry at each level, so a full table is skipped and the next
// one is tried. It gives up after MaxTablesPerMapping tables
template<typename T>
bool MapPhysicalToVirtual(address PhysicalAddress, T &&Callback, pagesize PageSize = Page_4KB)
{
    // While the dedicated table is linked, a 4 KB mapping takes a slot in it. If it has no free slot, the search below runs
    if (PageSize == Page_4KB && MapTableEntries && MapInDedicatedTable(PhysicalAddress, Callback)) return true;

    // Local variables. They are per call, so concurrent callers never share mapping state
    int Opened = 0;
    cr3 CR3 = read_cr3();
    address VA{};

    // PML4: every present entry leads to a PDPT
    address PML4Table = win::MmGetVirtualForPhysical({CR3.pml4_frame_number << 12});
    for (int PML4_IDX = 0; PML4_IDX < 512; ++PML4_IDX)
    {
        pml4e *PML4E = &((pml4e *) PML4Table)[PML4_IDX];
        if (!PML4E->present) continue;
        if (++Opened > MaxTablesPerMapping) return false;

        // PDPT
        address PDPTTable = win::MmGetVirtualForPhysical({PML4E->page_frame_number << 12});
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
            address PDTable = win::MmGetVirtualForPhysical({PDPTE->page_frame_number << 12});
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
                address PTTable = win::MmGetVirtualForPhysical({PDE->page_frame_number << 12});
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
    cr3 SystemCR3 = {((_KPROCESS *) win::PsInitialSystemProcess)->DirectoryTableBase};
    address TablePA{};
    pagesize PageSize{};
    if (!GetPhysicalAddress(address((uint64_t) MapTableStorage), SystemCR3, TablePA, PageSize)) return false;
    return LinkTable(SystemCR3, TablePA, MapTableStorage, MapTablePml4Index, MapTablePdptIndex, MapTablePdIndex);
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
