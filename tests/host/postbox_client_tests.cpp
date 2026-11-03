// ---------------------------------------------------------------------------
// Engine-ci/tests/host/postbox_client_tests.cpp
//
// Host-side tests for Engine-ci/User/pure.h — the PostboxClient argument
// parser, stop policy, and the protocol body-length helpers shared with the
// driver. No Win32, no BCrypt, no process/section calls.
//
// Compiled with NMI_PROBE/STACK_PROBE so the probe/status branches of the
// parser and body-length helper are exercised too.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../Common/Postbox.h"
#include "../../User/pure.h"

static unsigned g_Pass = 0;
static unsigned g_Fail = 0;

static void Report(bool ok, const char* file, unsigned line, const char* expr)
{
    if (ok) ++g_Pass;
    else { ++g_Fail; std::printf("[FAIL] %s:%u  %s\n", file, line, expr); }
}

#define CHECK(Cond) Report((Cond), __FILE__, __LINE__, #Cond)

static void TestParseMilliseconds()
{
    uint32_t v = 0;
    CHECK(ParseMilliseconds("0", v) && v == 0);
    CHECK(ParseMilliseconds("1000", v) && v == 1000);
    CHECK(ParseMilliseconds("4294967295", v) && v == 0xFFFFFFFFu);
    CHECK(!ParseMilliseconds("4294967296", v));       // overflow
    CHECK(!ParseMilliseconds("-1", v));               // sign
    CHECK(!ParseMilliseconds("+1", v));
    CHECK(!ParseMilliseconds("1x", v));               // trailing garbage
    CHECK(!ParseMilliseconds("", v));
    CHECK(!ParseMilliseconds(" 1", v));               // leading space
    CHECK(!ParseMilliseconds(nullptr, v));
}

static void TestParseArguments()
{
    {
        char exe[] = "postbox";
        char a1[] = "--hold"; char v1[] = "1000";
        char a2[] = "--hold-ping"; char v2[] = "250";
        char a3[] = "--loader"; char v3[] = "C:\\loader.exe";
        char a4[] = "--loader-args"; char v4[] = "--postbox 1 2";
        char a5[] = "--unknown"; char v5[] = "x";
        char* argv[] = {exe, a1, v1, a2, v2, a3, v3, a4, v4, a5, v5};
        ClientOptions o{};
        CHECK(ParseArguments(11, argv, o));
        CHECK(o.HoldMs == 1000);
        CHECK(o.HoldPingMs == 250);
        CHECK(o.LoaderPath && std::strcmp(o.LoaderPath, "C:\\loader.exe") == 0);
        CHECK(o.LoaderArgs && std::strcmp(o.LoaderArgs, "--postbox 1 2") == 0);
        CHECK(!o.Kill);
    }

    {
        char exe[] = "postbox";
        char a1[] = "--kill";
        char* argv[] = {exe, a1};
        ClientOptions o{};
        CHECK(ParseArguments(2, argv, o));
        CHECK(o.Kill);
    }

    {
        // missing values are hard errors
        char exe[] = "postbox";
        char a1[] = "--hold";
        char* argv[] = {exe, a1};
        ClientOptions o{};
        CHECK(!ParseArguments(2, argv, o));

        char bad[] = "-1";
        char* argvBad[] = {exe, a1, bad};
        ClientOptions o2{};
        CHECK(!ParseArguments(3, argvBad, o2));

        char over[] = "4294967296";
        char* argvOver[] = {exe, a1, over};
        ClientOptions o3{};
        CHECK(!ParseArguments(3, argvOver, o3));

        char a2[] = "--loader";
        char* argvNoLoader[] = {exe, a2};
        ClientOptions o4{};
        CHECK(!ParseArguments(2, argvNoLoader, o4));
    }

#ifdef NMI_PROBE
    {
        char exe[] = "postbox";
        char a1[] = "--nmi-probe";
        char a2[] = "--nmi-spin"; char v2[] = "12";
        char a3[] = "--nmi-status";
        char a4[] = "--nmi-gate-hold"; char v4[] = "34";
        char a5[] = "--nmi-gate-storm"; char v5[] = "56";
        char* argv[] = {exe, a1, a2, v2, a3, a4, v4, a5, v5};
        ClientOptions o{};
        CHECK(ParseArguments(9, argv, o));
        CHECK(o.NmiProbe && o.NmiStatus && o.NmiGate);
        CHECK(o.NmiSpinMs == 12 && o.NmiGateHoldMs == 34 && o.NmiGateStorm == 56);
    }
#endif
#ifdef STACK_PROBE
    {
        char exe[] = "postbox";
        char a1[] = "--stack-probe";
        char* argv[] = {exe, a1};
        ClientOptions o{};
        CHECK(ParseArguments(2, argv, o));
        CHECK(o.StackProbe);
    }
#endif
}

static void TestStopPlan()
{
    PostboxStopPlan p = PlanStopBestEffort(0);
    CHECK(!p.Submit && p.Seq == 0);

    p = PlanStopBestEffort(5);
    CHECK(p.Submit && p.Seq == 5);

    p = PlanStopBestEffort(0xFFFFFFFFu);
    CHECK(p.Submit && p.Seq == 0xFFFFFFFFu);
}

static void TestResponseBodyLengths()
{
    CHECK(PostboxResponseBodyLen(0, pb_read, 0x1234) == 0x1234);
    CHECK(PostboxResponseBodyLen(0, pb_nmi, 0) == sizeof(uint64_t));
    CHECK(PostboxResponseBodyLen(0, pb_ping, 8) == 0);
    CHECK(PostboxResponseBodyLen(0, pb_write, 8) == 0);
    CHECK(PostboxResponseBodyLen(0, pb_stop, 0) == 0);
    CHECK(PostboxResponseBodyLen(1, pb_read, 0x1234) == 0);

#ifdef NMI_PROBE
    CHECK(PostboxResponseBodyLen(0, pb_nmi_probe, 0) == sizeof(PostboxNmiProbeResult));
    CHECK(PostboxResponseBodyLen(0, pb_nmi_status, 0) == sizeof(PostboxNmiStatus));
#endif
#ifdef STACK_PROBE
    CHECK(PostboxResponseBodyLen(0, pb_stack_probe, 0) == sizeof(PostboxStackProbeResult));
#endif

    CHECK(PostboxRequestBodyLen(pb_write, 0x40) == 0x40);
    CHECK(PostboxRequestBodyLen(pb_read, 0x40) == 0);
}

int main()
{
    TestParseMilliseconds();
    TestParseArguments();
    TestStopPlan();
    TestResponseBodyLengths();

    std::printf("\n==== kf_postbox_client_tests: %u passed, %u failed ====\n",
                g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
