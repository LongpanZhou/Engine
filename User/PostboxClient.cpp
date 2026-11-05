// Postbox client: the user side of the timer/work-item channel. The mailbox is a normal
// private page owned by this process; the request loop does not touch the section or any
// cross-process API. Bootstrap uses one unnamed pagefile-backed section that carries
// {pid, VA, key, session, create time} to the loader. The client spawns the loader as a
// child with only that section handle inherited; there is no named Local\ object and no
// loader-side OpenFileMapping. The client pings automatically after the handshake.
#include <windows.h>
#include <bcrypt.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "../Common/Postbox.h"
#include "../Common/PostboxCrypto.h"
#include "pure.h"

struct ClientSession
{
    pb::PostboxKeys Keys;
    uint64_t SessionId;
    uint64_t Nonce;
    uint32_t Sequence;
    uint32_t Pid;
    int32_t Status;
    // Master key held only on this stack session until the loader is ready.
    // Keeping it out of a fixed .data global removes the V-06 static offset.
    uint8_t HandoffKey[32];
    bool HandoffKeyPending;

    ~ClientSession()
    {
        pb::WipePostboxKeys(&Keys);
        SecureZeroMemory(HandoffKey, sizeof(HandoffKey));
        HandoffKeyPending = false;
        SessionId = 0;
        Nonce = 0;
        Sequence = 0;
    }
};

// ClientOptions / ParseMilliseconds / ParseArguments / PlanStopBestEffort live in
// pure.h (host-unit-tested).

static bool RandomBytes(void* Buffer, size_t Size)
{
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(Buffer), static_cast<ULONG>(Size),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

// The master key must stay readable until the loader copies it. It lives in a
// one-page, pagefile-backed unnamed section. The client spawns the loader with
// only this handle inherited; the loader maps the inherited handle before any
// provider work, copies the record, and unmaps it. There is no name, no DACL
// to widen, and no process handle to the client.
//
// Cap the worst-case exposure at 60 s (the ping timeout): after that the first
// ping's wait loop wipes the section even if the loader never arrives. The working
// session keys are already derived, so the client keeps working if the loader was
// fast.
static HANDLE g_HandoffSection = nullptr;
static HANDLE g_LoaderProcess = nullptr;
static void* g_HandoffView = nullptr;
static ULONGLONG g_HandoffWipeAt = 0;
static ULONGLONG g_HandoffPublishedAt = 0;
constexpr ULONGLONG HandoffKeyGraceMs = 60000;

// The section is intentionally unnamed. The client keeps the creation handle and
// marks only that handle inheritable; the spawned loader receives it through the
// inherited handle table. There is no DACL to widen and no Local\ name for a
// same-user process to enumerate or open.
static bool CreateHandoffSection(const PostboxSectionHandoff& Handoff)
{
    HANDLE Section = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                                        PAGE_READWRITE, 0, PostboxSectionBytes, nullptr);
    if (!Section)
        return false;

    if (!SetHandleInformation(Section, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
    {
        CloseHandle(Section);
        return false;
    }

    void* View = MapViewOfFile(Section, FILE_MAP_WRITE, 0, 0, PostboxSectionBytes);
    if (!View)
    {
        CloseHandle(Section);
        return false;
    }

    std::memcpy(View, &Handoff, sizeof(Handoff));
    g_HandoffSection = Section;
    g_HandoffView = View;
    g_HandoffWipeAt = GetTickCount64() + HandoffKeyGraceMs;
    return true;
}

// Spawn the loader with the section handle inherited. The handle value is only
// meaningful inside the child's inherited handle table; the command line does
// not carry a name or a capability that another process can use.
//
// Std-handle plumbing (0x3B-before-main fix, see README "unusable console handle"):
// the restricted handle list used to hand the child nothing but the section, which
// leaves the console-subsystem loader without valid std handles and with a broken
// console attach state, faulting 0x3B in KiRestoreDebugRegisterState/KiSystemServiceExit
// before or around main(). The client's own redirected std handles (valid file or
// console handles under any parent) are marked inheritable, added to the handle-list
// restriction, and passed via STARTF_USESTDHANDLES so the CRT init is grounded. The
// GUI loader needs no console, so this is transparent for it; its evidence lines
// simply start reaching the redirected stdout as well.
static bool StartLoader(HANDLE Section, const ClientOptions& Options)
{
    if (!Section || !Options.LoaderPath || !Options.LoaderArgs)
        return false;

    char CommandLine[2048] = {};
    const int Written = std::snprintf(
        CommandLine, sizeof(CommandLine),
        "\"%s\" %s --postbox-handle 0x%llX",
        Options.LoaderPath, Options.LoaderArgs,
        static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(Section)));
    if (Written < 0 || Written >= static_cast<int>(sizeof(CommandLine)))
    {
        std::printf("postbox: loader command line is too long\n");
        return false;
    }

    // Gather the client's own std handles. Under cmd's `> log` redirection these are
    // real file handles; a NULL on any side falls back to the pre-fix behaviour, which
    // is safe for the GUI loader and must not regress it.
    HANDLE Std[3];
    Std[0] = GetStdHandle(STD_INPUT_HANDLE);
    Std[1] = GetStdHandle(STD_OUTPUT_HANDLE);
    Std[2] = GetStdHandle(STD_ERROR_HANDLE);
    bool HaveStd = true;
    for (int i = 0; i < 3; ++i)
    {
        if (Std[i])
        {
            // cmd's redirect targets are not inheritable by default; the child link
            // needs the flag so the handle-list entry is honoured.
            if (!SetHandleInformation(Std[i], HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
                HaveStd = false;
        }
        else
        {
            HaveStd = false;
        }
    }

    // Restrict inheritance to the handoff section plus, when valid, the std handles.
    // Without the handle list, bInheritHandles=TRUE hands the child every inheritable
    // handle in the client.
    STARTUPINFOEXA Si{};
    Si.StartupInfo.cb = sizeof(Si);
    SIZE_T AttrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 2, 0, &AttrSize);
    alignas(16) uint8_t AttrBuf[256] = {};
    if (AttrSize == 0 || AttrSize > sizeof(AttrBuf))
    {
        std::printf("postbox: attribute-list sizing failed\n");
        return false;
    }
    Si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(AttrBuf);
    if (!InitializeProcThreadAttributeList(Si.lpAttributeList, 2, 0, &AttrSize))
    {
        std::printf("postbox: attribute-list init failed, error %lu\n", GetLastError());
        return false;
    }
    HANDLE Inherit[4] = { Section, nullptr, nullptr, nullptr };
    DWORD InheritCount = 1;
    if (HaveStd)
    {
        Si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        Si.StartupInfo.hStdInput = Std[0];
        Si.StartupInfo.hStdOutput = Std[1];
        Si.StartupInfo.hStdError = Std[2];
        InheritCount = 4;   // section + the three std handles
        for (int i = 0; i < 3; ++i)
            Inherit[1 + i] = Std[i];
    }
    if (!UpdateProcThreadAttribute(Si.lpAttributeList, 0,
                                   PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                   Inherit, InheritCount * sizeof(Inherit[0]),
                                   nullptr, nullptr))
    {
        std::printf("postbox: handle-list setup failed, error %lu\n", GetLastError());
        DeleteProcThreadAttributeList(Si.lpAttributeList);
        return false;
    }

    PROCESS_INFORMATION Pi{};
    const BOOL Created = CreateProcessA(
        nullptr, CommandLine, nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT,
        nullptr, nullptr, &Si.StartupInfo, &Pi);
    DeleteProcThreadAttributeList(Si.lpAttributeList);
    if (!Created)
    {
        std::printf("postbox: CreateProcess(%s) failed, error %lu\n",
                    Options.LoaderPath, GetLastError());
        return false;
    }

    CloseHandle(Pi.hThread);
    g_LoaderProcess = Pi.hProcess;
    return true;
}

static void WipeHandoffSection(ClientSession& S)
{
    SecureZeroMemory(S.HandoffKey, sizeof(S.HandoffKey));
    S.HandoffKeyPending = false;
    g_HandoffPublishedAt = 0;
    if (g_HandoffView)
        SecureZeroMemory(g_HandoffView, PostboxSectionBytes);
}

// Publish the master key only after the loader has finished provider/map work
// and set LOADER_READY. The CAS claims PUBLISHING so the loader's withdrawal
// (timeout) wins cleanly. If the loader withdraws, the client wipes instead of
// leaving a key behind.
static void PublishHandoffKey(ClientSession& S)
{
    if (!g_HandoffView || !S.HandoffKeyPending) return;
    auto* Handoff = static_cast<PostboxSectionHandoff*>(g_HandoffView);
    if (Handoff->Reserved == PostboxSectionStateWithdrawn)
    {
        WipeHandoffSection(S);
        return;
    }
    if (Handoff->Reserved != PostboxSectionStateLoaderReady) return;
    if (InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&Handoff->Reserved),
                                   PostboxSectionStatePublishing,
                                   PostboxSectionStateLoaderReady) !=
        PostboxSectionStateLoaderReady)
    {
        if (Handoff->Reserved == PostboxSectionStateWithdrawn)
            WipeHandoffSection(S);
        return;
    }
    std::memcpy(Handoff->Key, S.HandoffKey, sizeof(Handoff->Key));
    MemoryBarrier();
    Handoff->Reserved = PostboxSectionStateKeyReady;
    SecureZeroMemory(S.HandoffKey, sizeof(S.HandoffKey));
    S.HandoffKeyPending = false;
    g_HandoffPublishedAt = GetTickCount64();
    std::printf("handoff: key published after loader-ready\n");
    std::fflush(stdout);
}

static void ExpireHandoffSection(ClientSession& S)
{
    PublishHandoffKey(S);
    if (g_HandoffView && !S.HandoffKeyPending)
    {
        auto* Handoff = static_cast<PostboxSectionHandoff*>(g_HandoffView);
        if (Handoff->Reserved == PostboxSectionStateWithdrawn)
        {
            WipeHandoffSection(S);
            return;
        }
        // If the loader never consumes the published key (timeout/unmap), do
        // not leave it resident until the 60 s grace.
        if (Handoff->Reserved != PostboxSectionStateConsumed &&
            g_HandoffPublishedAt != 0 &&
            GetTickCount64() - g_HandoffPublishedAt > 1000)
            WipeHandoffSection(S);
    }
    if (g_HandoffView && GetTickCount64() >= g_HandoffWipeAt)
        WipeHandoffSection(S);
}

static void CloseHandoffSection(ClientSession& S)
{
    WipeHandoffSection(S);
    if (g_HandoffView)
    {
        UnmapViewOfFile(g_HandoffView);
        g_HandoffView = nullptr;
    }
    if (g_HandoffSection)
    {
        CloseHandle(g_HandoffSection);
        g_HandoffSection = nullptr;
    }
}

static bool Submit(PostboxHeader* Header, uint8_t* Data, ClientSession& S,
                   uint32_t Op, uint64_t Address, uint32_t Size, uint32_t TimeoutMs,
                   uint32_t SeqOverride = 0)
{
    const uint32_t Seq = (SeqOverride != 0) ? SeqOverride : ++S.Sequence;
    const uint64_t Nonce = ++S.Nonce;

    // Clear the response side before publishing the request. A stale Ack == Seq can
    // otherwise make the wait return before the driver has run.
    Header->Seq = 0;
    Header->Ack = 0;
    Header->Status = 0;
    Header->Op = Op;
    Header->Pid = S.Pid;
    Header->Address = Address;
    Header->Size = Size;
    Header->Nonce = Nonce;
    Header->SessionId = S.SessionId;
    std::memset(Header->Mac, 0, sizeof(Header->Mac));

    if (Op == pb_write && Size != 0)
        pb::SealRequestBody(Data, Size, S.Keys, S.SessionId, Nonce);

    // Encrypt-then-MAC: seal the 20-byte header block, then MAC the ciphertext.
    pb::SealRequestHeader(reinterpret_cast<uint8_t*>(Header), S.Keys, S.SessionId, Nonce);
    uint8_t Tag[16];
    pb::MacRequestTag(Tag, S.Keys, S.SessionId, Seq, Nonce, Op,
                      reinterpret_cast<const uint8_t*>(Header), Data,
                      Op == pb_write ? Size : 0);
    std::memcpy(Header->Mac, Tag, sizeof(Tag));

    MemoryBarrier();
    Header->Seq = Seq;
    MemoryBarrier();

    const ULONGLONG Deadline = GetTickCount64() + TimeoutMs;
    while (GetTickCount64() < Deadline)
    {
        ExpireHandoffSection(S);
        if (Header->Ack == Seq) break;
        Sleep(1);
    }
    if (Header->Ack != Seq)
        return false;

    MemoryBarrier();

    // Latch the plaintext Status before it is MAC-verified; use that value for the tag
    // and decrypt length, then publish it to the caller. A post-MAC change to the mailbox
    // Status cannot alter what the caller trusts.
    const int32_t VerifiedStatus = Header->Status;
    const uint32_t ResponseBodyLen = PostboxResponseBodyLen(VerifiedStatus, Op, Size);
    uint8_t ResponseTag[16];
    pb::MacResponseTag(ResponseTag, S.Keys, S.SessionId, Seq, Header->Ack, VerifiedStatus,
                       Header->Nonce, Op, Data, ResponseBodyLen);
    if (!pb::Mac128Equal(ResponseTag, Header->Mac))
        return false;
    if (Header->Nonce != Nonce)
        return false;

    if (VerifiedStatus == 0)
    {
        if (Op == pb_read && Size != 0)
            pb::OpenResponseBody(Data, Size, S.Keys, S.SessionId, Nonce);
#ifdef NMI_PROBE
        else if (Op == pb_nmi_probe)
            pb::OpenResponseBody(Data, static_cast<uint32_t>(sizeof(PostboxNmiProbeResult)),
                                 S.Keys, S.SessionId, Nonce);
        else if (Op == pb_nmi_status)
            pb::OpenResponseBody(Data, static_cast<uint32_t>(sizeof(PostboxNmiStatus)),
                                 S.Keys, S.SessionId, Nonce);
#endif
#ifdef STACK_PROBE
        else if (Op == pb_stack_probe)
            pb::OpenResponseBody(Data, static_cast<uint32_t>(sizeof(PostboxStackProbeResult)),
                                 S.Keys, S.SessionId, Nonce);
#endif
        else if (Op == pb_nmi)
            pb::OpenResponseBody(Data, static_cast<uint32_t>(sizeof(uint64_t)), S.Keys,
                                 S.SessionId, Nonce);
    }
    S.Status = VerifiedStatus;
    return true;
}

// Best-effort teardown on an error path; the driver may already be gone.
// Reuse the last submitted Seq: if the driver did not process the request, this stop is
// LastSeq+1; if it did, it is LastSeq and the driver accepts a same-Seq stop.
static void StopBestEffort(PostboxHeader* Header, uint8_t* Data, ClientSession& S)
{
    const PostboxStopPlan Plan = PlanStopBestEffort(Header->Seq);
    if (Plan.Submit)
        (void) Submit(Header, Data, S, pb_stop, 0, 0, 1000, Plan.Seq);
}

// Keepalive hold: the driver stays on its fast timer, but no bulk/read requests are
// issued, so the mailbox is quiet except for pings. Hold runs
// only after the first ping/ACK, i.e. after the loader's bootstrap has already completed.
// Ping mode is also a liveness probe; a failure tears the session down like any other
// test failure.
static bool HoldSession(PostboxHeader* Header, uint8_t* Data, ClientSession& S,
                        uint32_t HoldMs, uint32_t HoldPingMs)
{
    const ULONGLONG Deadline = GetTickCount64() + HoldMs;

    if (HoldPingMs != 0)
    {
        std::printf("hold: %u ms, ping every %u ms\n",
                    static_cast<unsigned>(HoldMs), static_cast<unsigned>(HoldPingMs));
        std::fflush(stdout);
        for (;;)
        {
            if (GetTickCount64() >= Deadline)
                break;
            if (!Submit(Header, Data, S, pb_ping, 0, 0, 1000))
            {
                std::printf("hold: ping timeout or auth failure\n");
                StopBestEffort(Header, Data, S);
                return false;
            }
            if (S.Status != 0)
            {
                std::printf("hold: ping status=0x%X\n", static_cast<unsigned>(S.Status));
                StopBestEffort(Header, Data, S);
                return false;
            }

            const ULONGLONG Now = GetTickCount64();
            if (Now >= Deadline)
                break;
            const ULONGLONG Remaining = Deadline - Now;
            Sleep(static_cast<DWORD>(Remaining < HoldPingMs ? Remaining : HoldPingMs));
        }
        std::printf("hold: done\n");
        std::fflush(stdout);
        return true;
    }

    std::printf("hold: %u ms\n", static_cast<unsigned>(HoldMs));
    std::fflush(stdout);
    Sleep(HoldMs);
    return true;
}

int PostboxClientMain(int argc, char** argv)
{
    ClientOptions Options{};
    Options.LoaderPath = "mapload.exe";
    // Production default: no loader stdout blueprint. Test harnesses can override
    // with --loader-args when they need the loader's evidence lines.
    Options.LoaderArgs = "--sys DriverPlain.sys --provider pte --quiet";
    if (!ParseArguments(argc, argv, Options))
        return 1;

    // MEM_TOP_DOWN alone returns the same high address in every fresh process.
    // Allocate a random-size top-down pad first and keep it: the mailbox is then
    // placed below the pad at a varying offset. The pad is a private RW VAD with
    // no protocol data. The client prints the returned address for the loader.
    uint32_t PadSeed = 0;
    if (!RandomBytes(&PadSeed, sizeof(PadSeed)))
        PadSeed = GetTickCount();
    const SIZE_T PadBytes = (static_cast<SIZE_T>(1) + (PadSeed % 0xFF)) * 0x1000;
    void* Pad = VirtualAlloc(nullptr, PadBytes,
                             MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
    (void) Pad;

    // D-05: put a PAGE_NOACCESS guard on each side of the mailbox. The driver's
    // MailboxVa points at the middle page; a client-side overrun or underrun
    // faults instead of corrupting an adjacent allocation.
    constexpr SIZE_T MailboxGuard = 0x1000;
    void* MailboxAlloc = VirtualAlloc(nullptr, PostboxBytes + 2 * MailboxGuard,
                                      MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN,
                                      PAGE_READWRITE);
    if (!MailboxAlloc)
    {
        std::printf("postbox: VirtualAlloc failed, error %lu\n", GetLastError());
        return 1;
    }
    DWORD OldProtect = 0;
    if (!VirtualProtect(MailboxAlloc, MailboxGuard, PAGE_NOACCESS, &OldProtect) ||
        !VirtualProtect(static_cast<uint8_t*>(MailboxAlloc) + MailboxGuard + PostboxBytes,
                        MailboxGuard, PAGE_NOACCESS, &OldProtect))
    {
        std::printf("postbox: mailbox guard setup failed, error %lu\n", GetLastError());
        VirtualFree(MailboxAlloc, 0, MEM_RELEASE);
        return 1;
    }
    void* Base = static_cast<uint8_t*>(MailboxAlloc) + MailboxGuard;

    PostboxHeader* Header = static_cast<PostboxHeader*>(Base);
    std::memset(Base, 0, PostboxBytes);            // fault in all 16 mailbox pages
    uint8_t* Data = reinterpret_cast<uint8_t*>(Base) + PostboxDataAt;

    ClientSession S{};
    S.Pid = GetCurrentProcessId();

    uint8_t Master[32] = {};
    uint64_t SessionId = 0;
    if (!RandomBytes(Master, sizeof(Master)) || !RandomBytes(&SessionId, sizeof(SessionId)) ||
        SessionId == 0)
    {
        std::printf("postbox: BCryptGenRandom failed\n");
        return 1;
    }

    FILETIME CreateTime{}, ExitTime{}, KernelTime{}, UserTime{};
    if (!GetProcessTimes(GetCurrentProcess(), &CreateTime, &ExitTime, &KernelTime, &UserTime))
    {
        std::printf("postbox: GetProcessTimes failed, error %lu\n", GetLastError());
        return 1;
    }
    const uint64_t CreateTime64 =
        (static_cast<uint64_t>(CreateTime.dwHighDateTime) << 32) | CreateTime.dwLowDateTime;

    // Publish the bootstrap record in one unnamed pagefile-backed section before
    // spawning the loader. The mailbox body stays zeroed: there is no PBX1
    // signature or master key in the 64 KiB page.
    PostboxSectionHandoff Handoff{};
    Handoff.Magic = PostboxSectionHandoffMagic;
    Handoff.Version = PostboxSectionHandoffVersion;
    Handoff.Pid = S.Pid;
    Handoff.MailboxVa = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(Base));
    Handoff.SessionId = SessionId;
    Handoff.CreateTime = CreateTime64;
    Handoff.Reserved = PostboxSectionStateWaiting;
    std::memcpy(S.HandoffKey, Master, sizeof(S.HandoffKey));
    S.HandoffKeyPending = true;

    if (!CreateHandoffSection(Handoff))
    {
        SecureZeroMemory(&Handoff, sizeof(Handoff));
        SecureZeroMemory(S.HandoffKey, sizeof(S.HandoffKey));
        S.HandoffKeyPending = false;
        SecureZeroMemory(Master, sizeof(Master));
        std::printf("postbox: handoff section creation failed, error %lu\n", GetLastError());
        return 1;
    }
    SecureZeroMemory(&Handoff, sizeof(Handoff));

    if (!StartLoader(g_HandoffSection, Options))
    {
        SecureZeroMemory(Master, sizeof(Master));
        CloseHandoffSection(S);
        return 1;
    }

    // Derive the working keys from a copy; DerivePostboxKeys wipes its input.
    uint8_t MasterCopy[32];
    std::memcpy(MasterCopy, Master, sizeof(MasterCopy));
    pb::DerivePostboxKeys(&S.Keys, MasterCopy);
    SecureZeroMemory(Master, sizeof(Master));
    SecureZeroMemory(MasterCopy, sizeof(MasterCopy));
    S.SessionId = SessionId;

    std::printf("postbox: unnamed handoff section inherited by loader\n");
    std::printf("waiting up to 60 s for the driver...\n");
    std::fflush(stdout);

    // One ping stays in the mailbox until the driver starts: the timer's first work item
    // sees it. This makes the client/loader order irrelevant and keeps the lab scripted.
    if (!Submit(Header, Data, S, pb_ping, 0, 0, 60000))
    {
        std::printf("ping: timeout or auth failure (driver not mapped, wrong pid/VA/CreateTime, "
                    "or key/session mismatch)\n");
        CloseHandoffSection(S);
        return 1;
    }
    std::printf("ping: status=0x%X\n", static_cast<unsigned>(S.Status));
    if (S.Status != 0)
    {
        CloseHandoffSection(S);
        StopBestEffort(Header, Data, S);
        return 1;
    }

    // The loader has copied the handoff; do not leave the master key in the section.
    CloseHandoffSection(S);

    // Deterministic dead-client test: exit abruptly after a successful ping and the wipe,
    // with no pb_stop, so the driver must notice the client is gone on its own.
    if (Options.Kill)
    {
        std::printf("kill: terminating without pb_stop\n");
        std::fflush(stdout);
        // D-05: TerminateProcess skips the ClientSession destructor, so wipe the
        // working keys and the mailbox explicitly before the abrupt exit.
        pb::WipePostboxKeys(&S.Keys);
        SecureZeroMemory(Base, PostboxBytes);
        // Do not leave a fixed test exit code as a kill-path signature.
        uint32_t KillExit = 0;
        if (!RandomBytes(&KillExit, sizeof(KillExit)))
            KillExit = static_cast<uint32_t>(GetTickCount());
        TerminateProcess(GetCurrentProcess(), KillExit);
        std::printf("kill: TerminateProcess failed, error %lu\n", GetLastError());
        return 1;
    }

#ifdef POSTBOX_SELFTEST
    // The functional self-test is a test-client build, not the product client.
    // Compiling it out removes the fixed constants, invalid accesses, and test
    // strings from a shipping binary.
    if (Options.SelfTest)
    {
    int x = 9999;
    int y = 1111;
    if (!Submit(Header, Data, S, pb_read, reinterpret_cast<uint64_t>(&y), sizeof(y), 3000))
    {
        std::printf("read: timeout or auth failure\n");
        StopBestEffort(Header, Data, S);
        return 1;
    }
    std::memcpy(&x, Data, sizeof(x));
    std::printf("read: status=0x%X x=%d y=%d\n",
                static_cast<unsigned>(S.Status), x, y);
    if (S.Status != 0 || x != 1111 || y != 1111)
    {
        StopBestEffort(Header, Data, S);
        return 1;
    }
    SecureZeroMemory(Data, PostboxDataMax);

    x = 4242;
    std::memcpy(Data, &x, sizeof(x));
    if (!Submit(Header, Data, S, pb_write, reinterpret_cast<uint64_t>(&y), sizeof(y), 3000))
    {
        std::printf("write: timeout or auth failure\n");
        StopBestEffort(Header, Data, S);
        return 1;
    }
    std::printf("write: status=0x%X x=%d y=%d\n",
                static_cast<unsigned>(S.Status), x, y);
    if (S.Status != 0 || y != 4242)
    {
        StopBestEffort(Header, Data, S);
        return 1;
    }

    // Invalid read: the driver returns C0000005 with no body. This checks that an error
    // response (BodyLen=0) still verifies; the old client used the requested Size and
    // misreported every failed read as an auth failure.
    if (!Submit(Header, Data, S, pb_read, 1, sizeof(x), 3000))
    {
        std::printf("bad read: timeout or auth failure\n");
        StopBestEffort(Header, Data, S);
        return 1;
    }
    std::printf("bad read: status=0x%X\n", static_cast<unsigned>(S.Status));
    if (S.Status != static_cast<int32_t>(0xC0000005))
    {
        StopBestEffort(Header, Data, S);
        return 1;
    }

    // Write to a read-only user page: MmCopyVirtualMemory must return an access
    // violation instead of raising or silently modifying the page.
    void* RoPage = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (RoPage)
    {
        DWORD OldProtect = 0;
        VirtualProtect(RoPage, 0x1000, PAGE_READONLY, &OldProtect);
        x = 0xDEAD;
        std::memcpy(Data, &x, sizeof(x));
        if (!Submit(Header, Data, S, pb_write,
                    reinterpret_cast<uint64_t>(RoPage), sizeof(x), 3000))
        {
            std::printf("bad write: timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("bad write: status=0x%X\n", static_cast<unsigned>(S.Status));
        if (S.Status != static_cast<int32_t>(0xC0000005))
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }
        VirtualFree(RoPage, 0, MEM_RELEASE);
    }

    // Bulk path: exercises ~9 pages of the 16-page mailbox and a multi-page CopyVirtualMemory.
    static uint8_t Pattern[0x8000];
    static uint8_t Bulk[0x8000];
    for (uint32_t i = 0; i < sizeof(Pattern); ++i)
        Pattern[i] = static_cast<uint8_t>(i * 7 + 3);
    std::memset(Bulk, 0, sizeof(Bulk));
    std::memcpy(Data, Pattern, sizeof(Pattern));
    if (!Submit(Header, Data, S, pb_write, reinterpret_cast<uint64_t>(Bulk), sizeof(Bulk), 5000))
    {
        std::printf("bulk write: timeout or auth failure\n");
        StopBestEffort(Header, Data, S);
        return 1;
    }
    std::printf("bulk write: status=0x%X bytes=0x%X\n",
                static_cast<unsigned>(S.Status), static_cast<unsigned>(sizeof(Bulk)));

    std::memset(Data, 0, sizeof(Pattern));
    if (!Submit(Header, Data, S, pb_read, reinterpret_cast<uint64_t>(Bulk), sizeof(Bulk), 5000))
    {
        std::printf("bulk read: timeout or auth failure\n");
        SecureZeroMemory(Data, PostboxDataMax);
        StopBestEffort(Header, Data, S);
        return 1;
    }
    const bool BulkOk = S.Status == 0 && std::memcmp(Data, Pattern, sizeof(Bulk)) == 0;
    std::printf("bulk read: status=0x%X match=%d\n",
                static_cast<unsigned>(S.Status), BulkOk ? 1 : 0);
    if (!BulkOk)
    {
        SecureZeroMemory(Data, PostboxDataMax);
        StopBestEffort(Header, Data, S);
        return 1;
    }
    SecureZeroMemory(Data, PostboxDataMax);
    } // Options.SelfTest
#endif // POSTBOX_SELFTEST

#ifdef NMI_PROBE
    // Test-only constructed-IDT gate self-test: install the gate, deliver one
    // self-NMI, consume it in the stub, restore the Windows IDT, and report the
    // handled count. Chained hardware NMIs during the gated window are the
    // historical 0x3B source; run with the detector sending NMIs to reproduce.
    if (Options.NmiGate)
    {
        // Address=1: quick install/self-test/uninstall. Address=2: hold the gate
        // ~15 s for external chained NMIs. Address=3|count<<32: chained self-NMI
        // storm, deterministic and silent (no external NMI source). The hold and
        // storm modes report the stub's tick count (every NMI seen); the quick
        // mode reports the consumed self-test count.
        const bool Hold = Options.NmiGateHoldMs != 0;
        const bool Storm = Options.NmiGateStorm != 0;
        const uint64_t GateAddress = Storm
            ? (3ull | (static_cast<uint64_t>(Options.NmiGateStorm) << 32))
            : (Hold ? 2ull : 1ull);
        const uint32_t TimeoutMs = Storm
            ? Options.NmiGateStorm + 30000
            : (Hold ? Options.NmiGateHoldMs + 30000 : 30000);
        const char* Label = Storm ? " (storm)" : (Hold ? " (hold)" : "");
        const bool TicksMode = Storm || Hold;
        if (!Submit(Header, Data, S, pb_nmi, GateAddress, 0, TimeoutMs))
        {
            std::printf("nmi gate%s: timeout or auth failure\n", Label);
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("nmi gate%s: status=0x%X\n", Label,
                    static_cast<unsigned>(S.Status));
        if (S.Status != 0)
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }
        uint64_t Count = 0;
        std::memcpy(&Count, Data, sizeof(Count));
        std::printf("nmi gate%s: %s=%llu\n", Label,
                    TicksMode ? "ticks" : "handled",
                    static_cast<unsigned long long>(Count));
        std::fflush(stdout);
        SecureZeroMemory(Data, PostboxDataMax);
    }

    // Test-only NMI callback probe. The driver registers KeRegisterNmiCallback,
    // sends HalSendNMI to each core, and reports the interrupted machine frame.
    // InModule=0 for the mapped image is the expected detector hit; it proves the
    // callback saw execution outside PsLoadedModuleList.
    if (Options.NmiProbe)
    {
        if (!Submit(Header, Data, S, pb_nmi_probe, 0, 0, 20000))
        {
            std::printf("nmi probe: timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("nmi probe: status=0x%X\n", static_cast<unsigned>(S.Status));
        if (S.Status != 0)
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }

        PostboxNmiProbeResult Result{};
        std::memcpy(&Result, Data, sizeof(Result));
        uint32_t Cores = Result.CoreCount;
        if (Cores > PostboxNmiProbeMaxCores)
            Cores = PostboxNmiProbeMaxCores;
        for (uint32_t i = 0; i < Cores; ++i)
        {
            const PostboxNmiProbeCore& Core = Result.Core[i];
            std::printf("nmi core %u: count=%llu rip=%016llx rsp=%016llx user=%llu in_module=%llu\n",
                        static_cast<unsigned>(i),
                        static_cast<unsigned long long>(Core.Count),
                        static_cast<unsigned long long>(Core.Rip),
                        static_cast<unsigned long long>(Core.Rsp),
                        static_cast<unsigned long long>(Core.User),
                        static_cast<unsigned long long>(Core.InModule));
        }
        std::fflush(stdout);
        SecureZeroMemory(Data, PostboxDataMax);
    }

    // Test-only mapped-code window: hold the driver inside its own image so an
    // external NMI sampler (donnaskiez/nmi) can catch a RIP outside PsLoadedModuleList.
    if (Options.NmiSpinMs != 0)
    {
        const uint32_t SpinMs = Options.NmiSpinMs;
        if (!Submit(Header, Data, S, pb_nmi_probe, SpinMs, 0, SpinMs + 10000))
        {
            std::printf("nmi spin: timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("nmi spin: status=0x%X ms=%u\n",
                    static_cast<unsigned>(S.Status), static_cast<unsigned>(SpinMs));
        std::fflush(stdout);
        if (S.Status != 0)
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }
    }

    if (Options.NmiStatus)
    {
        // Test-only: prove the sanitizer activated (including after a late
        // detector load) and show the last record it rewrote.
        if (!Submit(Header, Data, S, pb_nmi_status, 0, 0, 5000))
        {
            std::printf("nmi status: timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("nmi status: status=0x%X\n", static_cast<unsigned>(S.Status));
        if (S.Status != 0)
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }
        PostboxNmiStatus St{};
        std::memcpy(&St, Data, sizeof(St));
        std::printf("nmi status: magic=0x%X active=%u ready=%u detector=%016llx+%llx writes=%llu last_core=%llu last_count=%llu last_user=%llu last_rip=%016llx last_rsp=%016llx refresh_active=%llu refresh_run=%llu refresh_count=%llu list=%016llx nt=%016llx+%llx pslist=%016llx apc_neutralized=%llu thread_start_spoofed=%llu dpc_routine=%016llx dpc_context=%016llx dpc_entry=%016llx\n",
                    St.Magic, St.Active, St.Ready,
                    static_cast<unsigned long long>(St.DetectorBase),
                    static_cast<unsigned long long>(St.DetectorSize),
                    static_cast<unsigned long long>(St.Writes),
                    static_cast<unsigned long long>(St.LastCore),
                    static_cast<unsigned long long>(St.LastCount),
                    static_cast<unsigned long long>(St.LastUser),
                    static_cast<unsigned long long>(St.LastRip),
                    static_cast<unsigned long long>(St.LastRsp),
                    static_cast<unsigned long long>(St.RefreshActive),
                    static_cast<unsigned long long>(St.RefreshRun),
                    static_cast<unsigned long long>(St.RefreshCount),
                    static_cast<unsigned long long>(St.ListHead),
                    static_cast<unsigned long long>(St.NtBase),
                    static_cast<unsigned long long>(St.NtSize),
                    static_cast<unsigned long long>(St.PsLoadedModuleList),
                    static_cast<unsigned long long>(St.ApcNeutralized),
                    static_cast<unsigned long long>(St.ThreadStartSpoofed),
                    static_cast<unsigned long long>(St.DpcDeferredRoutine),
                    static_cast<unsigned long long>(St.DpcDeferredContext),
                    static_cast<unsigned long long>(St.DpcEntry));
        std::fflush(stdout);
        SecureZeroMemory(Data, PostboxDataMax);
    }
#endif

#ifdef STACK_PROBE
    if (Options.StackProbe)
    {
        if (!Submit(Header, Data, S, pb_stack_probe, 0, 0, 5000))
        {
            std::printf("stack probe: timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::printf("stack probe: status=0x%X\n", static_cast<unsigned>(S.Status));
        if (S.Status != 0)
        {
            StopBestEffort(Header, Data, S);
            return 1;
        }

        PostboxStackProbeResult Result{};
        std::memcpy(&Result, Data, sizeof(Result));
        std::printf("stack probe: magic=0x%X hidden=%u gadget=%016llx real_rsp=%016llx fake_top=%016llx real_ret=%016llx spoof_gadget=%016llx spoof_ret=%016llx\n",
                    Result.Magic, Result.Hidden,
                    static_cast<unsigned long long>(Result.Gadget),
                    static_cast<unsigned long long>(Result.RealRsp),
                    static_cast<unsigned long long>(Result.FakeTop),
                    static_cast<unsigned long long>(Result.RealRet),
                    static_cast<unsigned long long>(Result.SpoofGadget),
                    static_cast<unsigned long long>(Result.SpoofRet));
        std::printf("stack walk: frames=%llu mapped_returns=%llu hits=%016llx %016llx %016llx %016llx\n",
                    static_cast<unsigned long long>(Result.StackScanned),
                    static_cast<unsigned long long>(Result.MappedHits),
                    static_cast<unsigned long long>(Result.Hit0),
                    static_cast<unsigned long long>(Result.Hit1),
                    static_cast<unsigned long long>(Result.Hit2),
                    static_cast<unsigned long long>(Result.Hit3));
        std::printf("stack raw: hits=%llu scanned=%llu (executable window, informational)\n",
                    static_cast<unsigned long long>(Result.RawHits),
                    static_cast<unsigned long long>(Result.RawScanned));
        std::fflush(stdout);
        SecureZeroMemory(Data, PostboxDataMax);
    }
#endif

    // Test-only hold: run after the functional tests, but before pb_stop, so the
    // driver keeps its fast timer for the duration.
    if (Options.HoldMs != 0)
    {
        if (!HoldSession(Header, Data, S, Options.HoldMs, Options.HoldPingMs))
            return 1;
    }

    if (Options.NmiStatus)
    {
        // Post-hold read: proves the APC stackwalk countermeasure ran while the
        // mapped threads were alive, not just during the short NMI window.
        if (Submit(Header, Data, S, pb_nmi_status, 0, 0, 5000))
        {
            PostboxNmiStatus St{};
            std::memcpy(&St, Data, sizeof(St));
            std::printf("apc status: neutralized=%llu active=%u writes=%llu thread_start_spoofed=%llu\n",
                        static_cast<unsigned long long>(St.ApcNeutralized),
                        St.Active,
                        static_cast<unsigned long long>(St.Writes),
                        static_cast<unsigned long long>(St.ThreadStartSpoofed));
            std::fflush(stdout);
            SecureZeroMemory(Data, PostboxDataMax);
        }
    }

    if (!Submit(Header, Data, S, pb_stop, 0, 0, 3000))
    {
        std::printf("stop: timeout or auth failure\n");
        return 1;
    }
    std::printf("stop: status=0x%X (timer cancelled; remap before the next run)\n",
                static_cast<unsigned>(S.Status));
    if (S.Status == 0)
        SecureZeroMemory(Base, PostboxBytes);

    // The loader owns provider cleanup after the channel stops. Wait for it so a
    // scripted caller that immediately queries services sees the final state.
    if (g_LoaderProcess)
    {
        WaitForSingleObject(g_LoaderProcess, 30000);
        CloseHandle(g_LoaderProcess);
        g_LoaderProcess = nullptr;
    }
    return S.Status == 0 ? 0 : 1;
}
