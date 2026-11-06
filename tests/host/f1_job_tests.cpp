// ---------------------------------------------------------------------------
// Engine-ci/tests/host/f1_job_tests.cpp
//
// Host-side tests for the job-only batch ABI and its pure validators. These tests
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

#include "check.h"
#include "../../Common/Postbox.h"
#include "../../Common/PostboxCrypto.h"
#include "../../Common/PostboxJobCrypto.h"

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
    for (uint32_t i = 0; i < sizeof(cfg.Key); ++i)
        cfg.Key[i] = static_cast<uint8_t>(i + 1);
    cfg.Mac = 0x123456789ABCDEF0ull;
    for (uint32_t i = 0; i < 7; ++i)
        cfg.Imports[i] = 0xFFFFF80000001000ull + i * 0x10;
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

    CHECK(sizeof(PostboxJobConfig) == 0x148);
    CHECK(offsetof(PostboxJobConfig, SectionVa) == 0x10);
    CHECK(offsetof(PostboxJobConfig, TargetPid) == 0x20);
    CHECK(offsetof(PostboxJobConfig, Nonce) == 0x30);
    CHECK(offsetof(PostboxJobConfig, Layout) == 0x58);
    CHECK(offsetof(PostboxJobConfig, Layout) == offsetof(PostboxConfig, Layout));
    CHECK(offsetof(PostboxJobConfig, Mac) == 0x108);
    CHECK(offsetof(PostboxJobConfig, Imports) == 0x110);

    CHECK(PostboxJobConfigMagic == 0x8F3A27C1);
    CHECK(PostboxJobConfigVersion == 2);
    CHECK(PostboxJobBatchMagic == 0x9B4D62E5);
    CHECK(PostboxJobBatchVersion == 2);
    CHECK(PostboxJobDoneMagic == 0xA7C3E91D5B28F064ull);
    CHECK(PostboxJobMax == 32);
    CHECK(PostboxJobMaxBytes == 0x10000);
    CHECK(PostboxJobSectionMax == 0x100000);
}

static void TestSectionHeader()
{
    CHECK(sizeof(PostboxJobSectionHeader) == 0x100);
    CHECK(offsetof(PostboxJobSectionHeader, Magic) == 0x00);
    CHECK(offsetof(PostboxJobSectionHeader, Version) == 0x04);
    CHECK(offsetof(PostboxJobSectionHeader, Count) == 0x08);
    CHECK(offsetof(PostboxJobSectionHeader, Flags) == 0x0C);
    CHECK(offsetof(PostboxJobSectionHeader, SectionSize) == 0x10);
    CHECK(offsetof(PostboxJobSectionHeader, TargetPid) == 0x18);
    CHECK(offsetof(PostboxJobSectionHeader, TargetCreateTime) == 0x20);
    CHECK(offsetof(PostboxJobSectionHeader, Nonce) == 0x28);
    CHECK(offsetof(PostboxJobSectionHeader, Key) == 0x30);
    CHECK(offsetof(PostboxJobSectionHeader, Mac) == 0x50);

    CHECK(PostboxJobSectionMagic == 0x8C4E71B3);
    CHECK(PostboxJobSectionVersion == 2);
    CHECK(PostboxJobSectionHeaderBytes == 0x100);
    CHECK(PostboxJobSectionBatchOffset == 0x100);
    CHECK(PostboxJobSectionBatchOffset + sizeof(PostboxJobBatch) <= 0x1000);
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
    CHECK(IsInvalid([](PostboxJobConfig& c) { c.Imports[3] = 0; }));
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
    auto IsValid = [&err](auto mutate) {
        PostboxJobConfig c = MakeValidConfig();
        mutate(c);
        return PostboxJobConfigValid(c, &err);
    };

    CHECK(IsValid([](PostboxJobConfig& c) {
        c.SectionVa = PostboxUserLimit - c.SectionSize;   // exact edge
    }));
    CHECK(IsValid([](PostboxJobConfig& c) {
        c.SectionSize = PostboxJobSectionMax;             // exact max
    }));
    CHECK(IsValid([](PostboxJobConfig& c) {
        c.Count = PostboxJobMax;                          // exact max
    }));
    CHECK(IsValid([](PostboxJobConfig& c) {
        c.TargetPid = 0;                                  // current process
        c.TargetCreateTime = 0;
    }));
    CHECK(IsValid([](PostboxJobConfig& c) {
        // v2 validates the full 32-byte master, not the v1 16-byte prefix.
        memset(c.Key, 0, sizeof(c.Key));
        c.Key[31] = 1;
    }));
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
    auto IsValid = [&err](auto mutate) {
        PostboxJobConfig c = MakeValidConfig();
        PostboxJobBatch b = MakeValidBatch(c);
        mutate(b);
        return PostboxJobBatchValid(b, c, &err);
    };

    CHECK(IsValid([](PostboxJobBatch& b) {
        b.Jobs[1].DataOffset = sizeof(PostboxJobBatch);    // first legal data offset
        b.Jobs[1].Size = 0x100;
    }));
    CHECK(IsValid([](PostboxJobBatch& b) {
        b.Jobs[1].Address = PostboxUserLimit - 0x100;      // exact end
        b.Jobs[1].Size = 0x100;
    }));
    CHECK(IsValid([](PostboxJobBatch& b) {
        b.Jobs[1].DataOffset = 0x3000 - 0x100;             // exact end
        b.Jobs[1].Size = 0x100;
    }));
    CHECK(IsValid([](PostboxJobBatch& b) {
        // A write job is valid with the same range rules.
        b.Jobs[1].Op = pb_job_write;
    }));
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

static void TestJobCrypto()
{
    uint8_t master[32] = {};
    for (uint32_t i = 0; i < sizeof(master); ++i)
        master[i] = static_cast<uint8_t>(0x40 + i);

    pb::PostboxKeys keys{};
    uint8_t masterCopy[32] = {};
    memcpy(masterCopy, master, sizeof(masterCopy));
    pb::DerivePostboxKeys(&keys, masterCopy);

    CHECK(AllBytesZero(masterCopy, sizeof(masterCopy)));

    PostboxJobConfig cfg = MakeValidConfig();
    PostboxJobBatch batch = MakeValidBatch(cfg);
    const PostboxJobBatch original = batch;
    const uint64_t nonce = cfg.Nonce;

    PostboxJobBatch sealed = batch;
    CHECK(pb::JobCryptBatch(&sealed, keys, nonce, false));
    CHECK(memcmp(&sealed, &batch, sizeof(batch)) != 0);

    const uint64_t mac = pb::JobBatchMac(keys, sealed);
    CHECK(mac == pb::JobBatchMac(keys, sealed));
    CHECK(mac != pb::JobBatchMac(keys, batch));

    PostboxJobBatch opened = sealed;
    CHECK(pb::JobCryptBatch(&opened, keys, nonce, false));
    CHECK(memcmp(&opened, &original, sizeof(batch)) == 0);

    // Request and result domains must not share a keystream.
    PostboxJobBatch result = original;
    CHECK(pb::JobCryptBatch(&result, keys, nonce, true));
    CHECK(memcmp(&result, &sealed, sizeof(batch)) != 0);
    PostboxJobBatch resultOpen = result;
    CHECK(pb::JobCryptBatch(&resultOpen, keys, nonce, true));
    CHECK(memcmp(&resultOpen, &original, sizeof(batch)) == 0);

    // A one-bit ciphertext change changes the tag.
    sealed.Jobs[1].Size ^= 1;
    CHECK(pb::JobBatchMac(keys, sealed) != mac);

    // Chunked sealing must continue one keystream: encrypting a 0x1000 buffer
    // at offset 0 equals two 0x800 encryptions at offsets 0 and 0x800.
    uint8_t whole[0x1000];
    uint8_t chunk0[0x800];
    uint8_t chunk1[0x800];
    for (uint32_t i = 0; i < sizeof(whole); ++i)
        whole[i] = static_cast<uint8_t>(i * 7u + 3u);
    memcpy(chunk0, whole, sizeof(chunk0));
    memcpy(chunk1, whole + 0x800, sizeof(chunk1));

    CHECK(pb::JobCryptData(whole, sizeof(whole), keys, nonce, 3, pb_job_read, 0));
    CHECK(pb::JobCryptData(chunk0, sizeof(chunk0), keys, nonce, 3, pb_job_read, 0));
    CHECK(pb::JobCryptData(chunk1, sizeof(chunk1), keys, nonce, 3, pb_job_read, 0x800));
    CHECK(memcmp(whole, chunk0, sizeof(chunk0)) == 0);
    CHECK(memcmp(whole + 0x800, chunk1, sizeof(chunk1)) == 0);

    // Domain separation: the same bytes under the write direction do not open
    // with the read direction.
    uint8_t wrong[0x800];
    memcpy(wrong, chunk0, sizeof(wrong));
    CHECK(pb::JobCryptData(wrong, sizeof(wrong), keys, nonce, 3, pb_job_write, 0));
    CHECK(memcmp(wrong, chunk0, sizeof(wrong)) != 0);

    CHECK(pb::JobDataDomain(1, pb_job_read) != pb::JobDataDomain(1, pb_job_write));
    CHECK(pb::JobDataDomain(1, pb_job_read) != pb::JobDataDomain(2, pb_job_read));

    uint8_t small[64] = {};
    CHECK(!pb::JobCryptData(small, sizeof(small), keys, nonce, 0, pb_job_read, 1));
}

// End-to-end ABI flow without a kernel: controller seals a request, the driver
// side authenticates/opens/validates it, then the driver seals a result and the
// controller opens it. This pins the version handshake and the MAC coverage.
static void TestBatchSealFlow()
{
    PostboxJobConfig cfg = MakeValidConfig();
    for (uint32_t i = 0; i < 32; ++i)
        cfg.Key[i] = static_cast<uint8_t>(0xA0 + i);

    pb::PostboxKeys keys{};
    uint8_t masterCopy[32] = {};
    memcpy(masterCopy, cfg.Key, sizeof(masterCopy));
    pb::DerivePostboxKeys(&keys, masterCopy);

    PostboxJobBatch request = MakeValidBatch(cfg);
    const PostboxJobBatch plain = request;
    CHECK(pb::JobCryptBatch(&request, keys, cfg.Nonce, false));
    const uint64_t mac = pb::JobBatchMac(keys, request);
    cfg.Mac = mac;

    // Driver side: authenticate the ciphertext, open it, validate it.
    CHECK(pb::JobBatchMac(keys, request) == cfg.Mac);
    PostboxJobBatch opened = request;
    CHECK(pb::JobCryptBatch(&opened, keys, cfg.Nonce, false));
    CHECK(memcmp(&opened, &plain, sizeof(plain)) == 0);
    uint32_t err = 0xFFFF;
    CHECK(PostboxJobBatchValid(opened, cfg, &err));
    CHECK(err == 0);

    // Sealed write data: controller seals, driver opens, bytes round-trip.
    uint8_t data[0x200];
    for (uint32_t i = 0; i < sizeof(data); ++i)
        data[i] = static_cast<uint8_t>(i ^ 0x5A);
    uint8_t sealedData[sizeof(data)];
    memcpy(sealedData, data, sizeof(data));
    CHECK(pb::JobCryptData(sealedData, sizeof(sealedData), keys, cfg.Nonce,
                           1, pb_job_write, 0));
    CHECK(pb::JobCryptData(sealedData, sizeof(sealedData), keys, cfg.Nonce,
                           1, pb_job_write, 0));
    CHECK(memcmp(sealedData, data, sizeof(data)) == 0);

    // Driver side: seal the result batch and mark it done.
    PostboxJobBatch result = opened;
    result.Jobs[1].Status = 0;
    result.Jobs[1].Done = result.Jobs[1].Size;
    result.Reserved = PostboxJobDoneMagic;
    CHECK(pb::JobCryptBatch(&result, keys, cfg.Nonce, true));

    // Controller side: open and check.
    PostboxJobBatch resultOpen = result;
    CHECK(pb::JobCryptBatch(&resultOpen, keys, cfg.Nonce, true));
    CHECK(resultOpen.Reserved == PostboxJobDoneMagic);
    CHECK(resultOpen.Count == cfg.Count);
    CHECK(resultOpen.Jobs[1].Done == resultOpen.Jobs[1].Size);
}

int main()
{
    TestAbi();
    TestSectionHeader();
    TestConfigValid();
    TestBatchValid();
    TestBatchMac();
    TestJobCrypto();
    TestBatchSealFlow();

    return Summary("kf_f1_job_tests");
}
