// Postbox client: the user side of the timer/work-item channel. The mailbox is a normal
// private page owned by this process; there is no section, no handle, and no syscall in
// the request loop. Run this first, note the printed pid/VA, then run mapload with
// --postbox <pid> <va>; the client pings automatically.
#include <windows.h>
#include <bcrypt.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "../Common/Postbox.h"
#include "../Common/PostboxCrypto.h"

struct ClientSession
{
    pb::PostboxKeys Keys;
    uint64_t SessionId;
    uint64_t Nonce;
    uint32_t Sequence;
    uint32_t Pid;
    int32_t Status;

    ~ClientSession()
    {
        pb::WipePostboxKeys(&Keys);
        SessionId = 0;
        Nonce = 0;
        Sequence = 0;
    }
};

// Test-only client modes. Defaults reproduce the original --nmi-less behavior exactly.
struct ClientOptions
{
    bool Nmi;
    bool Kill;
    uint32_t HoldMs;
    uint32_t HoldPingMs;
    const char* HandoffPath;
};

static bool RandomBytes(void* Buffer, size_t Size)
{
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(Buffer), static_cast<ULONG>(Size),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
}

// The PBK1 master key must stay readable until the loader copies it. The loader
// reads it after provider bring-up and before the entry call; normal runs take a
// few seconds. Cap the worst-case exposure at 60 s (the ping timeout): after that the first ping's
// wait loop wipes the key even if the loader never arrives. The working session
// keys are already derived, so the client keeps working if the loader was fast.
static volatile uint8_t* g_HandoffKey = nullptr;
static ULONGLONG g_HandoffWipeAt = 0;
constexpr ULONGLONG HandoffKeyGraceMs = 60000;

static void ExpireHandoffKey()
{
    if (g_HandoffKey && GetTickCount64() >= g_HandoffWipeAt)
    {
        uint8_t* Base = const_cast<uint8_t*>(g_HandoffKey) - offsetof(PostboxHandoff, Key);
        SecureZeroMemory(Base, sizeof(PostboxHandoff));
        g_HandoffKey = nullptr;
    }
}

static void WipeHandoff(uint8_t* Data)
{
    SecureZeroMemory(Data, sizeof(PostboxHandoff));
    g_HandoffKey = nullptr;
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
        ExpireHandoffKey();
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
    const uint32_t ResponseBodyLen =
        VerifiedStatus != 0 ? 0 :
        (Op == pb_read) ? Size :
        (Op == pb_nmi) ? static_cast<uint32_t>(sizeof(uint64_t)) : 0;
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
    const uint32_t Seq = Header->Seq;
    if (Seq != 0)
        (void) Submit(Header, Data, S, pb_stop, 0, 0, 1000, Seq);
}

// Strict non-negative decimal parse; anything strtoul would silently accept
// (empty string, sign, trailing garbage) is rejected.
static bool ParseMilliseconds(const char* Text, uint32_t& Out)
{
    if (!Text || *Text == '\0')
        return false;
    uint64_t Value = 0;
    for (const char* p = Text; *p; ++p)
    {
        if (*p < '0' || *p > '9')
            return false;
        Value = Value * 10 + static_cast<uint64_t>(*p - '0');
        if (Value > 0xFFFFFFFFull)
            return false;
    }
    Out = static_cast<uint32_t>(Value);
    return true;
}

// Flags may appear in any order. Unrecognized arguments are ignored, which keeps the
// User.exe entry point working: it forwards its own "--postbox" as argv[1].
static bool ParseArguments(int argc, char** argv, ClientOptions& Options)
{
    for (int i = 1; i < argc; ++i)
    {
        const char* Arg = argv[i];
        if (std::strcmp(Arg, "--nmi") == 0)
        {
            Options.Nmi = true;
        }
        else if (std::strcmp(Arg, "--kill") == 0)
        {
            Options.Kill = true;
        }
        else if (std::strcmp(Arg, "--hold") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.HoldMs))
            {
                std::printf("postbox: --hold requires a millisecond value\n");
                return false;
            }
            ++i;
        }
        else if (std::strcmp(Arg, "--hold-ping") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.HoldPingMs))
            {
                std::printf("postbox: --hold-ping requires a millisecond value\n");
                return false;
            }
            ++i;
        }
        else if (std::strcmp(Arg, "--handoff") == 0)
        {
            if (i + 1 >= argc)
            {
                std::printf("postbox: --handoff requires a file path\n");
                return false;
            }
            Options.HandoffPath = argv[++i];
        }
    }
    return true;
}

// Keepalive hold: the driver stays on its fast timer and the NMI gate stays active, but
// no bulk/read requests are issued, so the mailbox is quiet except for pings. Hold runs
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
    void* Base = VirtualAlloc(nullptr, PostboxBytes,
                              MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE);
    if (!Base)
    {
        std::printf("postbox: VirtualAlloc failed, error %lu\n", GetLastError());
        return 1;
    }

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

    // Write the handoff before printing the pid/VA, so the loader can read it as soon as
    // it starts. The ping has Size = 0 and does not disturb these bytes.
    PostboxHandoff* Handoff = reinterpret_cast<PostboxHandoff*>(Data);
    Handoff->Magic = PostboxHandoffMagic;
    Handoff->Version = 1;
    Handoff->SessionId = SessionId;
    Handoff->CreateTime = CreateTime64;
    std::memcpy(Handoff->Key, Master, sizeof(Handoff->Key));
    g_HandoffKey = Handoff->Key;
    g_HandoffWipeAt = GetTickCount64() + HandoffKeyGraceMs;

    // Derive the working keys from a copy; DerivePostboxKeys wipes its input.
    uint8_t MasterCopy[32];
    std::memcpy(MasterCopy, Master, sizeof(MasterCopy));
    pb::DerivePostboxKeys(&S.Keys, MasterCopy);
    SecureZeroMemory(Master, sizeof(Master));
    SecureZeroMemory(MasterCopy, sizeof(MasterCopy));
    S.SessionId = SessionId;

    // Optional out-of-band handoff: the loader reads the PID/VA from this file
    // instead of argv, so the loader command line does not disclose the target.
    // The file carries only PID/VA (not the key) and the loader deletes it.
    if (Options.HandoffPath)
    {
        FILE* f = nullptr;
        if (fopen_s(&f, Options.HandoffPath, "w") == 0 && f)
        {
            std::fprintf(f, "%lu 0x%llX\n", static_cast<unsigned long>(S.Pid),
                         static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(Base)));
            std::fclose(f);
        }
    }

    std::printf("postbox: pid=%lu va=0x%llX size=0x%X\n",
                static_cast<unsigned long>(S.Pid),
                static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(Base)), PostboxBytes);
    if (Options.HandoffPath)
        std::printf("run: mapload.exe --sys Driver.sys --provider pte --postbox-file %s\n",
                    Options.HandoffPath);
    else
        std::printf("run: mapload.exe --sys Driver.sys --provider pte --postbox %lu 0x%llX\n",
                    static_cast<unsigned long>(S.Pid),
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(Base)));
    std::printf("waiting up to 60 s for the driver...\n");
    std::fflush(stdout);

    // One ping stays in the mailbox until the driver starts: the timer's first work item
    // sees it. This makes the client/loader order irrelevant and keeps the lab scripted.
    if (!Submit(Header, Data, S, pb_ping, 0, 0, 60000))
    {
        std::printf("ping: timeout or auth failure (driver not mapped, wrong pid/VA/CreateTime, "
                    "or key/session mismatch)\n");
        WipeHandoff(Data);
        return 1;
    }
    std::printf("ping: status=0x%X\n", static_cast<unsigned>(S.Status));
    if (S.Status != 0)
    {
        WipeHandoff(Data);
        StopBestEffort(Header, Data, S);
        return 1;
    }

    // The driver has consumed the handoff; do not leave the master key in the mailbox.
    WipeHandoff(Data);

    // Deterministic dead-client test: exit abruptly after a successful ping and the wipe,
    // with no pb_stop, so the driver must notice the client is gone on its own.
    if (Options.Kill)
    {
        std::printf("kill: terminating without pb_stop\n");
        std::fflush(stdout);
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        std::printf("kill: TerminateProcess failed, error %lu\n", GetLastError());
        return 1;
    }

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

    if (Options.Nmi)
    {
        uint64_t NmiBefore = 0;
        if (!Submit(Header, Data, S, pb_nmi, 0, 0, 3000))
        {
            std::printf("nmi: query timeout or unsupported (driver not built with POSTBOX_NMI)\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        if (S.Status != 0)
        {
            std::printf("nmi: query status=0x%X\n", static_cast<unsigned>(S.Status));
            StopBestEffort(Header, Data, S);
            return 1;
        }
        std::memcpy(&NmiBefore, Data, sizeof(NmiBefore));
        std::printf("nmi: count=%llu\n", static_cast<unsigned long long>(NmiBefore));

        if (!Submit(Header, Data, S, pb_nmi, 1, 0, 3000))
        {
            std::printf("nmi: self-test timeout or auth failure\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
        if (S.Status != 0)
        {
            std::printf("nmi: self-test status=0x%X\n", static_cast<unsigned>(S.Status));
            StopBestEffort(Header, Data, S);
            return 1;
        }
        uint64_t NmiHandled = 0;
        std::memcpy(&NmiHandled, Data, sizeof(NmiHandled));
        std::printf("nmi: self-test handled=%llu\n",
                    static_cast<unsigned long long>(NmiHandled));
        SecureZeroMemory(Data, PostboxDataMax);
        if (NmiHandled == 0)
        {
            std::printf("nmi: self-test did not consume an NMI\n");
            StopBestEffort(Header, Data, S);
            return 1;
        }
    }

    // Test-only hold: run after the functional tests and the optional NMI checks, but
    // before pb_stop, so the driver keeps its fast timer and NMI gate for the duration.
    if (Options.HoldMs != 0)
    {
        if (!HoldSession(Header, Data, S, Options.HoldMs, Options.HoldPingMs))
            return 1;
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
    return S.Status == 0 ? 0 : 1;
}
