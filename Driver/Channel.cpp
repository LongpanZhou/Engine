// Shared-memory command channel: replaces the NtCompareSigningLevels hook.
//
// The driver creates Global\EngineCiShared, maps it into system space and runs
// one system thread that services requests placed in the section by User.exe.
// Nothing in ntoskrnl is patched, so PatchGuard has nothing to compare here and
// there is no pointer to restore on unload.
//
// Unity order (main.cpp): after Process.cpp, before Traces.cpp
#include "../Common/Command.h"

// Minimal kernel-side layouts, kept local so the channel does not depend on the
// vendor headers declaring these types
struct ChannelUnicodeString
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
};

struct ChannelObjectAttributes
{
    uint32_t Length;
    uint32_t Pad0;
    void* RootDirectory;
    ChannelUnicodeString* ObjectName;
    uint32_t Attributes;
    uint32_t Pad1;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
};

static_assert(sizeof(ChannelObjectAttributes) == 0x30, "OBJECT_ATTRIBUTES must be 0x30 bytes");

using FnZwCreateSection = int32_t (*)(void**, uint32_t, ChannelObjectAttributes*, int64_t*, uint32_t, uint32_t, void*);
using FnObReferenceObjectByHandle = int32_t (*)(void*, uint32_t, void*, int32_t, void**, void*);
using FnMmMapViewInSystemSpace = int32_t (*)(void*, void**, size_t*);
using FnMmUnmapViewInSystemSpace = int32_t (*)(void*);
using FnZwClose = int32_t (*)(void*);
using FnObfDereferenceObject = void (*)(void*);
using FnPsCreateSystemThread = int32_t (*)(void**, uint32_t, ChannelObjectAttributes*, void*, void (*)(void*), void*);
using FnPsTerminateSystemThread = int32_t (*)(int32_t);
using FnKeDelayExecutionThread = int32_t (*)(uint8_t, uint8_t, int64_t*);
using FnKeWaitForSingleObject = int32_t (*)(void*, uint32_t, uint8_t, uint8_t, int64_t*);

static address ChannelCreateSection = 0;
static address ChannelRefByHandle = 0;
static address ChannelMapSystem = 0;
static address ChannelUnmapSystem = 0;
static address ChannelClose = 0;
static address ChannelDeref = 0;
static address ChannelCreateThread = 0;
static address ChannelTerminateThread = 0;
static address ChannelDelayThread = 0;
static address ChannelWaitObject = 0;

static void* ChannelSection = nullptr;
static void* ChannelBase = nullptr;
static void* ChannelThreadHandle = nullptr;
static volatile long ChannelRunning = 0;
static uint32_t ChannelLastSequence = 0;

static constexpr uint32_t kSectionAllAccess = 0x000F001F;
static constexpr uint32_t kPageReadWrite = 0x04;
static constexpr uint32_t kSecCommit = 0x08000000;
static constexpr uint32_t kThreadAllAccess = 0x001FFFFF;
static constexpr uint32_t kObjCaseInsensitive = 0x00000040;
static constexpr uint32_t kObjKernelHandle = 0x00000200;

// Runs one request that is already visible in the section
static void ChannelProcess(ChannelHeader* Header)
{
    Header->Status = 0;

    if (Header->Op == op_ping)
    {
        Header->Heartbeat++;
        return;
    }

    if (Header->Op != op_read && Header->Op != op_write)
    {
        Header->Status = (int32_t) 0xC0000010;   // STATUS_INVALID_DEVICE_REQUEST
        return;
    }

    if (!Header->RemoteAddress || !Header->TargetPid || Header->Size > ChannelDataMax)
    {
        Header->Status = (int32_t) 0xC000000D;   // STATUS_INVALID_PARAMETER
        return;
    }

    _EPROCESS* Process = EnumerateEProcess(L"", Header->TargetPid);
    if (!Process)
    {
        Header->Status = (int32_t) 0xC000000B;   // STATUS_INVALID_CID
        return;
    }

    const cr3 TargetCr3 = ((_KPROCESS*) Process)->DirectoryTableBase;
    const address Data = (address) ((uint8_t*) ChannelBase + ChannelDataAt);
    const bool Write = Header->Op == op_write;

    if (!AccessVirtualMemory((address) Header->RemoteAddress, TargetCr3, Data, Header->Size, Write))
        Header->Status = (int32_t) 0xC0000005;   // STATUS_ACCESS_VIOLATION
}

static void ChannelThread(void*)
{
    ChannelHeader* Header = (ChannelHeader*) ChannelBase;

    while (__atomic_load_n(&ChannelRunning, __ATOMIC_ACQUIRE))
    {
        const uint32_t Sequence = __atomic_load_n(&Header->Sequence, __ATOMIC_ACQUIRE);
        if (Sequence != ChannelLastSequence)
        {
            ChannelLastSequence = Sequence;
            ChannelProcess(Header);
            __atomic_store_n(&Header->Ack, Sequence, __ATOMIC_RELEASE);
        }

        int64_t Interval = -10000;   // 1 ms
        ((FnKeDelayExecutionThread) ChannelDelayThread)(0, 0, &Interval);
    }

    ((FnPsTerminateSystemThread) ChannelTerminateThread)(0);
}

static bool ChannelResolve()
{
    address Ntoskrnl = GetNtoskrnl();
    if (!Ntoskrnl)
    {
        print(ERROR("Channel: ntoskrnl not found"));
        return false;
    }

    static const char* const Names[] = {
        "ZwCreateSection",
        "ObReferenceObjectByHandle",
        "MmMapViewInSystemSpace",
        "MmUnmapViewInSystemSpace",
        "ZwClose",
        "ObfDereferenceObject",
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "KeDelayExecutionThread",
        "KeWaitForSingleObject",
    };

    address Functions[10] = {};
    FindFuncExportsBatch(Ntoskrnl, Names, Functions, 10);

    ChannelCreateSection = Functions[0];
    ChannelRefByHandle = Functions[1];
    ChannelMapSystem = Functions[2];
    ChannelUnmapSystem = Functions[3];
    ChannelClose = Functions[4];
    ChannelDeref = Functions[5];
    ChannelCreateThread = Functions[6];
    ChannelTerminateThread = Functions[7];
    ChannelDelayThread = Functions[8];
    ChannelWaitObject = Functions[9];

    for (uint32_t i = 0; i < 10; ++i)
    {
        if (!Functions[i])
        {
            print(ERROR("Channel: export %s not found"), Names[i]);
            return false;
        }
    }
    return true;
}

// Creates the named section, maps it into system space and starts the worker
bool ChannelStart()
{
    if (ChannelBase) return true;
    if (!ChannelResolve()) return false;

    static const wchar_t kNameBuffer[] = L"\\BaseNamedObjects\\EngineCiShared";
    ChannelUnicodeString Name;
    Name.Buffer = (wchar_t*) kNameBuffer;
    Name.Length = (uint16_t) ((sizeof(kNameBuffer) / sizeof(wchar_t) - 1) * sizeof(wchar_t));
    Name.MaximumLength = (uint16_t) (Name.Length + sizeof(wchar_t));

    ChannelObjectAttributes Attributes = {};
    Attributes.Length = sizeof(Attributes);
    Attributes.ObjectName = &Name;
    Attributes.Attributes = kObjCaseInsensitive | kObjKernelHandle;

    int64_t MaximumSize = ChannelBytes;
    void* SectionHandle = nullptr;
    int32_t Status = ((FnZwCreateSection) ChannelCreateSection)(
        &SectionHandle, kSectionAllAccess, &Attributes, &MaximumSize,
        kPageReadWrite, kSecCommit, nullptr);
    if (Status < 0)
    {
        print(ERROR("Channel: ZwCreateSection failed 0x%x"), (uint32_t) Status);
        return false;
    }

    void* Section = nullptr;
    Status = ((FnObReferenceObjectByHandle) ChannelRefByHandle)(
        SectionHandle, kSectionAllAccess, nullptr, 0, &Section, nullptr);
    ((FnZwClose) ChannelClose)(SectionHandle);
    if (Status < 0)
    {
        print(ERROR("Channel: ObReferenceObjectByHandle failed 0x%x"), (uint32_t) Status);
        return false;
    }
    ChannelSection = Section;

    size_t ViewSize = ChannelBytes;
    Status = ((FnMmMapViewInSystemSpace) ChannelMapSystem)(Section, &ChannelBase, &ViewSize);
    if (Status < 0)
    {
        print(ERROR("Channel: MmMapViewInSystemSpace failed 0x%x"), (uint32_t) Status);
        ChannelBase = nullptr;
        ((FnObfDereferenceObject) ChannelDeref)(Section);
        ChannelSection = nullptr;
        return false;
    }

    uint8_t* Bytes = (uint8_t*) ChannelBase;
    for (uint32_t i = 0; i < ChannelDataAt; ++i) Bytes[i] = 0;
    ((ChannelHeader*) ChannelBase)->Magic = ChannelMagic;

    __atomic_store_n(&ChannelRunning, 1, __ATOMIC_RELEASE);

    void* ThreadHandle = nullptr;
    Status = ((FnPsCreateSystemThread) ChannelCreateThread)(
        &ThreadHandle, kThreadAllAccess, nullptr, nullptr, ChannelThread, nullptr);
    if (Status < 0)
    {
        print(ERROR("Channel: PsCreateSystemThread failed 0x%x"), (uint32_t) Status);
        __atomic_store_n(&ChannelRunning, 0, __ATOMIC_RELEASE);
        ((FnMmUnmapViewInSystemSpace) ChannelUnmapSystem)(ChannelBase);
        ChannelBase = nullptr;
        ((FnObfDereferenceObject) ChannelDeref)(Section);
        ChannelSection = nullptr;
        return false;
    }
    ChannelThreadHandle = ThreadHandle;

    print(INFO("Channel: %s live at %p"), "Global\\EngineCiShared", ChannelBase);
    return true;
}

// Stops the worker, then releases the view and the section object. Only the SCM
// path reaches this today; a manually mapped image has no unload callback, so
// its thread lives until the machine goes down.
void ChannelStop()
{
    if (__atomic_load_n(&ChannelRunning, __ATOMIC_ACQUIRE))
    {
        __atomic_store_n(&ChannelRunning, 0, __ATOMIC_RELEASE);
        if (ChannelThreadHandle && ChannelWaitObject)
        {
            int64_t Timeout = -10000000;   // 1 s
            ((FnKeWaitForSingleObject) ChannelWaitObject)(ChannelThreadHandle, 0, 0, 0, &Timeout);
        }
    }

    if (ChannelThreadHandle)
    {
        ((FnZwClose) ChannelClose)(ChannelThreadHandle);
        ChannelThreadHandle = nullptr;
    }
    if (ChannelBase)
    {
        ((FnMmUnmapViewInSystemSpace) ChannelUnmapSystem)(ChannelBase);
        ChannelBase = nullptr;
    }
    if (ChannelSection)
    {
        ((FnObfDereferenceObject) ChannelDeref)(ChannelSection);
        ChannelSection = nullptr;
    }
}
