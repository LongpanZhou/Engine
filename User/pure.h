#pragma once
// ---------------------------------------------------------------------------
// Engine-ci/User/pure.h — PostboxClient helpers with no Win32 calls, kept here
// so the host unit tests can exercise the argument parser and stop policy.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>

// Test-only client modes.
struct ClientOptions
{
    bool Kill;
    uint32_t HoldMs;
    uint32_t HoldPingMs;
    const char* LoaderPath;
    const char* LoaderArgs;
#ifdef POSTBOX_SELFTEST
    // The read/write/invalid/bulk sequence is a test harness, not a product
    // default. It is compiled only into the explicit test client.
    bool SelfTest;
#endif
#ifdef NMI_PROBE
    bool NmiProbe;
    uint32_t NmiSpinMs;
    bool NmiStatus;
    bool NmiGate;
    uint32_t NmiGateHoldMs;
    uint32_t NmiGateStorm;
#endif
#ifdef STACK_PROBE
    bool StackProbe;
#endif
};

// Strict non-negative decimal parse; anything strtoul would silently accept
// (empty string, sign, trailing garbage) is rejected.
inline bool ParseMilliseconds(const char* Text, uint32_t& Out)
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
inline bool ParseArguments(int argc, char** argv, ClientOptions& Options)
{
    for (int i = 1; i < argc; ++i)
    {
        const char* Arg = argv[i];
        if (std::strcmp(Arg, "--kill") == 0)
        {
            Options.Kill = true;
        }
#ifdef POSTBOX_SELFTEST
        else if (std::strcmp(Arg, "--selftest") == 0)
        {
            Options.SelfTest = true;
        }
#endif
        else if (std::strcmp(Arg, "--hold") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.HoldMs))
            {
                std::printf("postbox: --hold requires a millisecond value\n");
                return false;
            }
            ++i;
        }
#ifdef NMI_PROBE
        else if (std::strcmp(Arg, "--nmi-probe") == 0)
        {
            Options.NmiProbe = true;
        }
        else if (std::strcmp(Arg, "--nmi-spin") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.NmiSpinMs))
            {
                std::printf("postbox: --nmi-spin requires a millisecond value\n");
                return false;
            }
            ++i;
        }
        else if (std::strcmp(Arg, "--nmi-status") == 0)
        {
            Options.NmiStatus = true;
        }
        else if (std::strcmp(Arg, "--nmi-gate") == 0)
        {
            Options.NmiGate = true;
        }
        else if (std::strcmp(Arg, "--nmi-gate-hold") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.NmiGateHoldMs))
            {
                std::printf("postbox: --nmi-gate-hold requires a millisecond value\n");
                return false;
            }
            ++i;
            Options.NmiGate = true;
        }
        else if (std::strcmp(Arg, "--nmi-gate-storm") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.NmiGateStorm))
            {
                std::printf("postbox: --nmi-gate-storm requires a count\n");
                return false;
            }
            ++i;
            Options.NmiGate = true;
        }
#endif
#ifdef STACK_PROBE
        else if (std::strcmp(Arg, "--stack-probe") == 0)
        {
            Options.StackProbe = true;
        }
#endif
        else if (std::strcmp(Arg, "--hold-ping") == 0)
        {
            if (i + 1 >= argc || !ParseMilliseconds(argv[i + 1], Options.HoldPingMs))
            {
                std::printf("postbox: --hold-ping requires a millisecond value\n");
                return false;
            }
            ++i;
        }
        else if (std::strcmp(Arg, "--loader") == 0)
        {
            if (i + 1 >= argc)
            {
                std::printf("postbox: --loader requires a path\n");
                return false;
            }
            Options.LoaderPath = argv[++i];
        }
        else if (std::strcmp(Arg, "--loader-args") == 0)
        {
            if (i + 1 >= argc)
            {
                std::printf("postbox: --loader-args requires a string\n");
                return false;
            }
            Options.LoaderArgs = argv[++i];
        }
    }
    return true;
}

// Error-path stop policy: reuse the last submitted sequence. If the driver did
// not process the request this stop is LastSeq+1; if it did, it is LastSeq and
// the driver accepts a same-Seq stop. A zero header sequence means nothing was
// submitted, so there is nothing to stop.
struct PostboxStopPlan
{
    bool Submit;
    uint32_t Seq;
};

inline PostboxStopPlan PlanStopBestEffort(uint32_t HeaderSeq)
{
    return {HeaderSeq != 0, HeaderSeq};
}
