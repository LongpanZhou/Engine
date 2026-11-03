// ---------------------------------------------------------------------------
// Engine-ci/tests/host/f1_job_tests.cpp
//
// Host-side tests for the F1 Job-post ABI and its pure validators. These tests
// do not touch the kernel: they pin the struct sizes/offsets the loader and the
// driver share, and every accept/reject branch that runs before the driver
// touches the job section.
//
// Build/run:
//   clang++ -O0 -std=c++23 -DDEBUG f1_job_tests.cpp -o f1_job_tests.exe
//   f1_job_tests.exe
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../../Common/Postbox.h"
#include "../../Common/PostboxCrypto.h"

static unsigned g_Pass = 0;
static unsigned g_Fail = 0;

static void Report(bool ok, const char* file, unsigned line, const char* expr)
{
    if (ok) { ++g_Pass; return; }
    ++g_Fail;
    std::printf("FAIL %s:%u: %s\n", file, line, expr);
}

#define CHECK(expr) Report((expr), __FILE__, __LINE__, #expr)

static PostboxJobConfig MakeValidConfig()
{
    PostboxJobConfig cfg{};
    cfg.Magic = PostboxJobConfigMagic;
    cfg.Version = PostboxJobConfigVersion;
    cfg.Count = 2;
    cfg.SectionVa = 0x1F0000;
    cfg.SectionSize = 0x3000;
    cfg.TargetPid = 1234;
    cfg.TargetCreateTime = 0x1122334455667788ull;
    cfg.Nonce = 0x99AABBCCDDEEFF00ull;
    for (uint32_t i = 0; i < 16; ++i)
        cfg.Key[i] = static_cast<uint8_t>(i + 1);
    cfg.Mac = 0x123456789ABCDEF0ull;
    cfg.Layout.Magic = PostboxLayoutMagic;
    cfg.Layout.Version = PostboxLayoutVersion;
    cfg.Layout.ImageSize = 0xB000;
    cfg.Layout.SectionCount = 1;
    cfg.Layout.ImageBase = 0xFFFF810000000000ull;
    cfg.Layout.AllocSize = 0xB000;
    cfg.Layout.NtoskrnlBase = 0xFFFFF8012C600000ull;
    cfg.Layout.Sections[0].Rva = 0x1000;
    cfg.Layout.Sections[0].Size = 0xA000;
    cfg.Layout.Sections[0].Flags = PostboxPageRx;
    return cfg;
}

static PostboxJobBatch MakeValidBatch(const PostboxJobConfig& cfg)
{
    PostboxJobBatch batch{};
    batch.Magic = PostboxJobBatchMagic;
    batch.Version = PostboxJobBatchVersion;
    batch.Count = cfg.Count;
    batch.TargetPid = cfg.TargetPid;
    batch.TargetCreateTime = cfg.TargetCreateTime;
    batch.Nonce = cfg.Nonce;

    batch.Jobs[0].Op = pb_job_ping;
    batch.Jobs[1].Op = pb_job_read;
    batch.Jobs[1].Address = 0x10000;
    batch.Jobs[1].Size = 0x100;
    batch.Jobs[1].DataOffset = 0x1000;
    return batch;
}

static void TestAbi()
{
    CHECK(sizeof(PostboxJobRecord) == 0x28);
    CHECK(offsetof(PostboxJobRecord, Op) == 0x00);
    CHECK(offsetof(PostboxJobRecord, Status) == 0x04);
    CHECK(offsetof(PostboxJobRecord, Size) == 0x08);
    CHECK(offsetof(PostboxJobRecord, Done) == 0x0C);
    CHECK(offsetof(PostboxJobRecord, Address) == 0x10);
    CHECK(offsetof(PostboxJobRecord, DataOffset) == 0x18);

    CHECK(sizeof(PostboxJobBatch) == 0x530);
    CHECK(offsetof(PostboxJobBatch, Jobs) == 0x30);
    CHECK(sizeof(PostboxJobBatch::Jobs) / sizeof(PostboxJobRecord) == PostboxJobMax);

    CHECK(sizeof(PostboxJobConfig) == 0x110);
    CHECK(offsetof(PostboxJobConfig, SectionVa) == 0x10);
    CHECK(offsetof(PostboxJobConfig, TargetPid) == 0x20);
    CHECK(offsetof(PostboxJobConfig, Nonce) == 0x30);
    CHECK(offsetof(PostboxJobConfig, Layout) == 0x58);
    CHECK(offsetof(PostboxJobConfig, Layout) == offsetof(PostboxConfig, Layout));
    CHECK(offsetof(PostboxJobConfig, Mac) == 0x108);

    CHECK(PostboxJobConfigMagic == 0x8F3A27C1);
    CHECK(PostboxJobBatchMagic == 0x9B4D62E5);
    CHECK(PostboxJobDoneMagic == 0xA7C3E91D5B28F064ull);
    CHECK(PostboxJobMax == 32);
    CHECK(PostboxJobMaxBytes == 0x10000);
    CHECK(PostboxJobSectionMax == 0x100000);
}

static void TestConfigValid()
{
    auto IsInvalid = [](auto mutate) {
        PostboxJobConfig cfg = MakeValidConfig();
        mutate(cfg);
        uint32_t err = 0xFFFF;
        return !PostboxJobConfigValid(cfg, &err) && err == 40;
    };

    PostboxJobConfig cfg = MakeValidConfig();
    uint32_t err = 0xFFFF;
    CHECK(PostboxJobConfigValid(cfg, &err));
    CHECK(err == 0);

    // Pure: validation must not mutate the config.
    const PostboxJobConfig snapshot = cfg;
    CHECK(PostboxJobConfigValid(cfg, &err));
    CHECK(memcmp(&snapshot, &cfg, sizeof(cfg)) == 0);

    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Magic = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Version = PostboxJobConfigVersion - 1; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Reserved = 1; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { memset(c.Key, 0, sizeof(c.Key)); }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.SectionVa = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.SectionVa = 0x1004; }));   // unaligned
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.SectionSize = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.SectionSize = sizeof(PostboxJobBatch) - 1; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.SectionSize = PostboxJobSectionMax + 0x1000; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) {
        c.SectionVa = PostboxUserLimit - c.SectionSize + 8;
    }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Count = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Count = PostboxJobMax + 1; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.TargetCreateTime = 0; }));       // cross-process
    CHECK(IsInvalid([](PostboxJobConfig& c) {
        c.TargetPid = 0;                                                        // same-process
        c.TargetCreateTime = 1;
    }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.TargetPid = 0x100000000ull; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Layout.Magic = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Layout.Version = PostboxLayoutVersion - 1; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Layout.NtoskrnlBase = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Layout.ImageBase = 0; }));
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Layout.AllocSize = 0; }));

    // Edges that must be accepted.
    {
        PostboxJobConfig c = MakeValidConfig();
        c.SectionVa = PostboxUserLimit - c.SectionSize;   // exact edge
        CHECK(PostboxJobConfigValid(c, &err));
    }
    {
        PostboxJobConfig c = MakeValidConfig();
        c.SectionSize = PostboxJobSectionMax;             // exact max
        CHECK(PostboxJobConfigValid(c, &err));
    }
    {
        PostboxJobConfig c = MakeValidConfig();
        c.Count = PostboxJobMax;                          // exact max
        CHECK(PostboxJobConfigValid(c, &err));
    }
    {
        PostboxJobConfig c = MakeValidConfig();
        c.TargetPid = 0;                                  // current process
        c.TargetCreateTime = 0;
        CHECK(PostboxJobConfigValid(c, &err));
    }
    {
        PostboxJobConfig ok = MakeValidConfig();
        CHECK(PostboxJobConfigValid(ok));                 // error output optional
        ok.Magic = 0;
        CHECK(!PostboxJobConfigValid(ok));
    }
}

static void TestBatchValid()
{
    auto IsInvalid = [](auto mutate) {
        PostboxJobConfig cfg = MakeValidConfig();
        PostboxJobBatch batch = MakeValidBatch(cfg);
        mutate(batch);
        uint32_t err = 0xFFFF;
        return !PostboxJobBatchValid(batch, cfg, &err) && err == 41;
    };

    PostboxJobConfig cfg = MakeValidConfig();
    PostboxJobBatch batch = MakeValidBatch(cfg);
    uint32_t err = 0xFFFF;
    CHECK(PostboxJobBatchValid(batch, cfg, &err));
    CHECK(err == 0);

    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Magic = 0; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Version = PostboxJobBatchVersion - 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Flags = 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Reserved = 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Reserved = PostboxJobDoneMagic; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[0].Reserved = 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Count = 0; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Count = PostboxJobMax + 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Count = 1; }));       // config says 2
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.TargetPid++; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.TargetCreateTime++; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Nonce++; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[1].Op = 99; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[1].Size = PostboxJobMaxBytes + 1; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[1].Size = 0; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[1].Address = 0; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[1].Address = PostboxUserLimit; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) {
        b.Jobs[1].Address = PostboxUserLimit - 0x10;
        b.Jobs[1].Size = 0x20;
    }));
    CHECK(IsInvalid([](PostboxJobBatch& b) {
        b.Jobs[1].DataOffset = sizeof(PostboxJobBatch) - 1;
    }));
    CHECK(IsInvalid([](PostboxJobBatch& b) {
        b.Jobs[1].DataOffset = 0x2F01;                 // section 0x3000, size 0x100
    }));
    CHECK(IsInvalid([](PostboxJobBatch& b) {
        b.Jobs[1].Size = 0x10000;                      // larger than the section
        b.Jobs[1].DataOffset = 0x1000;
    }));
    CHECK(IsInvalid([](PostboxJobBatch& b) {
        b.Jobs[0].Size = 1;                            // ping must be all-zero
    }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[0].Address = 0x1000; }));
    CHECK(IsInvalid([](PostboxJobBatch& b) { b.Jobs[0].DataOffset = 0x1000; }));

    // Edges that must be accepted.
    {
        PostboxJobBatch b = MakeValidBatch(cfg);
        b.Jobs[1].DataOffset = sizeof(PostboxJobBatch);    // first legal data offset
        b.Jobs[1].Size = 0x100;
        CHECK(PostboxJobBatchValid(b, cfg, &err));
    }
    {
        PostboxJobBatch b = MakeValidBatch(cfg);
        b.Jobs[1].Address = PostboxUserLimit - 0x100;      // exact end
        b.Jobs[1].Size = 0x100;
        CHECK(PostboxJobBatchValid(b, cfg, &err));
    }
    {
        PostboxJobBatch b = MakeValidBatch(cfg);
        b.Jobs[1].DataOffset = 0x3000 - 0x100;             // exact end
        b.Jobs[1].Size = 0x100;
        CHECK(PostboxJobBatchValid(b, cfg, &err));
    }
    {
        // A write job is valid with the same range rules.
        PostboxJobConfig c = MakeValidConfig();
        PostboxJobBatch b = MakeValidBatch(c);
        b.Jobs[1].Op = pb_job_write;
        CHECK(PostboxJobBatchValid(b, c, &err));
    }
    {
        PostboxJobConfig ok = MakeValidConfig();
        PostboxJobBatch b = MakeValidBatch(ok);
        CHECK(PostboxJobBatchValid(b, ok));                // error output optional
        b.Magic = 0;
        CHECK(!PostboxJobBatchValid(b, ok));
    }
}

static void TestBatchMac()
{
    PostboxJobConfig cfg = MakeValidConfig();
    PostboxJobBatch batch = MakeValidBatch(cfg);
    uint8_t key[16] = {};
    for (uint32_t i = 0; i < sizeof(key); ++i)
        key[i] = static_cast<uint8_t>(0x80 + i);

    const uint64_t mac1 = pb::SipHash24(key, &batch, sizeof(batch));
    batch.Jobs[1].Size ^= 1;
    const uint64_t mac2 = pb::SipHash24(key, &batch, sizeof(batch));
    CHECK(mac1 != mac2);

    batch.Jobs[1].Size ^= 1;
    CHECK(pb::SipHash24(key, &batch, sizeof(batch)) == mac1);

    uint8_t other[16] = {};
    memcpy(other, key, sizeof(other));
    other[0] ^= 1;
    CHECK(pb::SipHash24(other, &batch, sizeof(batch)) != mac1);
}

int main()
{
    TestAbi();
    TestConfigValid();
    TestBatchValid();
    TestBatchMac();

    std::printf("\n==== kf_f1_job_tests: %u passed, %u failed ====\n", g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
