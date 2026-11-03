// ---------------------------------------------------------------------------
// Engine-ci/tests/host/postbox_crypto_tests.cpp
//
// Host-side unit tests for Engine-ci/Common/PostboxCrypto.h — the
// authenticated-mailbox crypto layer (ChaCha20, SipHash-2-4, key schedule,
// request/response MACs, seal/open helpers, header field accessors).
//
// Correctness strategy: the primitives are pinned against an independent
// reference vector (RFC 8439 ChaCha20 block KAT, SipHash-2-4 reference vector),
// and the protocol layer is pinned against an INDEPENDENTLY encoded canonical
// byte string, so a field-order change in MacRequestInit/MacResponseInit
// cannot pass by affecting both sides equally.
//
// The header is freestanding (no Win32, no allocation), so these tests compile
// with the same clang64 toolchain as the driver tests. No kernel/VM involved.
//
// Debug-only by the runner script's gate; never ships.
// No external framework: micro harness of CHECK() counters, exit code
// 0 == all green.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

#include "../../Common/Postbox.h"
#include "../../Common/PostboxCrypto.h"

// ---------------------------------------------------------------------------
// Micro harness
// ---------------------------------------------------------------------------

static unsigned g_Pass = 0;
static unsigned g_Fail = 0;

static void Report(bool ok, const char* file, unsigned line, const char* expr)
{
    if (ok) ++g_Pass;
    else { ++g_Fail; std::printf("[FAIL] %s:%u  %s\n", file, line, expr); }
}

#define CHECK(Cond) Report((Cond), __FILE__, __LINE__, #Cond)

static void MakeKeys(pb::PostboxKeys* keys, uint8_t seed)
{
    uint8_t master[32] = {};
    for (uint32_t i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(i * 7 + seed);
    pb::DerivePostboxKeys(keys, master);
}

// Independent little-endian writers for the canonical MAC inputs.
struct Canon
{
    uint8_t Bytes[160];
    size_t N = 0;

    void U8(uint8_t v) { Bytes[N++] = v; }
    void U16(uint16_t v) { Bytes[N++] = static_cast<uint8_t>(v); Bytes[N++] = static_cast<uint8_t>(v >> 8); }
    void U32(uint32_t v) { for (unsigned i = 0; i < 4; ++i) Bytes[N++] = static_cast<uint8_t>(v >> (8 * i)); }
    void U64(uint64_t v) { for (unsigned i = 0; i < 8; ++i) Bytes[N++] = static_cast<uint8_t>(v >> (8 * i)); }
    void Raw(const void* p, size_t n) { memcpy(Bytes + N, p, n); N += n; }
};

// ===========================================================================
// 1. Primitive reference vectors
// ===========================================================================

static void TestSipHashReferenceVector()
{
    // SipHash-2-4 reference-implementation (Aumasson/Bernstein) vector:
    // key = 00 01 .. 0f, empty message -> 726fdb47dd0e0e31. (SipHash has no RFC;
    // the value is from the reference vectors, not RFC 6194.)
    const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    CHECK(pb::SipHash24(key, nullptr, 0) == 0x726fdb47dd0e0e31ull);
    CHECK(pb::SipHash24(key, "", 0) == 0x726fdb47dd0e0e31ull);
}

static void TestSipHashIncremental()
{
    // Streaming Update/Final must equal the one-shot hash for every length and
    // every split point (exercises the buffered-block path in SipHashUpdate).
    const uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t msg[80];
    for (uint32_t i = 0; i < sizeof(msg); ++i) msg[i] = static_cast<uint8_t>(i * 11 + 5);

    for (uint32_t len = 0; len <= sizeof(msg); len += 7)
    {
        const uint64_t oneShot = pb::SipHash24(key, msg, len);
        for (uint32_t split = 0; split <= len; ++split)
        {
            pb::SipHashState s;
            pb::SipHashInit(&s, key);
            pb::SipHashUpdate(&s, msg, split);
            pb::SipHashUpdate(&s, msg + split, len - split);
            CHECK(pb::SipHashFinal(&s) == oneShot);
        }
    }
}

static void TestChaCha20BlockRfc8439()
{
    // RFC 8439 section 2.3.2 — ChaCha20 block function test vector:
    // key 00..1F, nonce 00 00 00 09 00 00 00 4A 00 00 00 00, counter 1.
    // This is the independent check for the quarter-round and state layout.
    const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F};
    const uint8_t nonce[12] = {0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4A,0x00,0x00,0x00,0x00};
    const uint8_t expected[64] = {
        0x10,0xF1,0xE7,0xE4, 0xD1,0x3B,0x59,0x15, 0x50,0x0F,0xDD,0x1F, 0xA3,0x20,0x71,0xC4,
        0xC7,0xD1,0xF4,0xC7, 0x33,0xC0,0x68,0x03, 0x04,0x22,0xAA,0x9A, 0xC3,0xD4,0x6C,0x4E,
        0xD2,0x82,0x64,0x46, 0x07,0x9F,0xAA,0x09, 0x14,0xC2,0xD7,0x05, 0xD9,0x8B,0x02,0xA2,
        0xB5,0x12,0x9C,0xD1, 0xDE,0x16,0x4E,0xB9, 0xCB,0xD0,0x83,0xE8, 0xA2,0x50,0x3C,0x4E};

    uint8_t out[64] = {};
    pb::ChaCha20Block(out, key, nonce, 1);
    CHECK(memcmp(out, expected, sizeof(expected)) == 0);
}

static void TestChaChaSigmaMask()
{
    // The driver stores the "expand 32-byte k" sigma XOR-masked so the mapped
    // image carries no plaintext crypto constant. Verify the products.
    CHECK((0x3B2A223Fu ^ 0x5A5A5A5Au) == 0x61707865ul);  // "expa"
    CHECK((0x697A3E34u ^ 0x5A5A5A5Au) == 0x3320646Eul);  // "nd 3"
    CHECK((0x23387768u ^ 0x5A5A5A5Au) == 0x79622D32ul);  // "2-by"
    CHECK((0x317A3F2Eu ^ 0x5A5A5A5Au) == 0x6B206574ul);  // "te k"
}

static void TestChaChaBlocksFor()
{
    CHECK(pb::ChaCha20BlocksFor(0) == 0);
    CHECK(pb::ChaCha20BlocksFor(1) == 1);
    CHECK(pb::ChaCha20BlocksFor(63) == 1);
    CHECK(pb::ChaCha20BlocksFor(64) == 1);
    CHECK(pb::ChaCha20BlocksFor(65) == 2);
    CHECK(pb::ChaCha20BlocksFor(pb::kMaxBodyBytes) == pb::kMaxBodyBlocks);   // 1023
    CHECK(pb::kMaxBodyBlocks == 1023);
}

static void TestChaChaCounterWrap()
{
    const uint8_t key[32] = {};
    const uint8_t nonce[12] = {};
    uint8_t out[512];
    memset(out, 0xAA, sizeof(out));

    // 512 bytes = 8 blocks. The product rejects only when
    // counter + blocks > 2^32:
    //   0xFFFFFFF8 + 8 == 2^32   -> exactly fits, allowed
    //   0xFFFFFFF9 + 8 == 2^32+1 -> wraps, rejected (and writes nothing)
    CHECK(pb::ChaCha20Keystream(out, 512, key, nonce, 0xFFFFFFF8u));
    memset(out, 0xAA, sizeof(out));
    CHECK(!pb::ChaCha20Keystream(out, 512, key, nonce, 0xFFFFFFF9u));
    bool untouched = true;
    for (uint32_t i = 0; i < sizeof(out); ++i)
        if (out[i] != 0xAA) untouched = false;
    CHECK(untouched);

    // a single block at the very top of the counter space is valid
    CHECK(pb::ChaCha20Keystream(out, 64, key, nonce, 0xFFFFFFFFu));
    // ... but one byte more needs a second block and wraps
    CHECK(!pb::ChaCha20Keystream(out, 65, key, nonce, 0xFFFFFFFFu));
}

static void TestChaChaXorWrapReject()
{
    const uint8_t key[32] = {};
    const uint8_t nonce[12] = {};
    uint8_t out[512];
    memset(out, 0xAA, sizeof(out));

    CHECK(!pb::ChaCha20Xor(out, 512, key, nonce, 0xFFFFFFF9u));   // 8 blocks wrap
    bool untouched = true;
    for (uint32_t i = 0; i < sizeof(out); ++i)
        if (out[i] != 0xAA) untouched = false;
    CHECK(untouched);

    CHECK(!pb::ChaCha20Xor(out, 128, key, nonce, 0xFFFFFFFFu));   // 2 blocks wrap
    CHECK(pb::ChaCha20Xor(out, 0, key, nonce, 0xFFFFFFFFu));      // zero length ok
}

static void TestChaChaXorSymmetry()
{
    const uint8_t key[32] = {};
    const uint8_t nonce[12] = {};
    uint8_t data[96];
    for (uint32_t i = 0; i < sizeof(data); ++i) data[i] = static_cast<uint8_t>(i);
    uint8_t copy[sizeof(data)];
    memcpy(copy, data, sizeof(data));

    CHECK(pb::ChaCha20Xor(data, sizeof(data), key, nonce, 0));
    CHECK(memcmp(data, copy, sizeof(data)) != 0);
    CHECK(pb::ChaCha20Xor(data, sizeof(data), key, nonce, 0));
    CHECK(memcmp(data, copy, sizeof(data)) == 0);

    // a nonzero counter also round-trips, and different counters give
    // different keystreams
    CHECK(pb::ChaCha20Xor(data, sizeof(data), key, nonce, 7));
    CHECK(pb::ChaCha20Xor(data, sizeof(data), key, nonce, 7));
    CHECK(memcmp(data, copy, sizeof(data)) == 0);

    uint8_t a[64], b[64];
    CHECK(pb::ChaCha20Keystream(a, sizeof(a), key, nonce, 0));
    CHECK(pb::ChaCha20Keystream(b, sizeof(b), key, nonce, 1));
    CHECK(memcmp(a, b, sizeof(a)) != 0);
}

// ===========================================================================
// 2. Key schedule
// ===========================================================================

static void TestDerivePostboxKeys()
{
    uint8_t master[32];
    uint8_t masterCopy[32];
    for (uint32_t i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(i * 3 + 1);
    memcpy(masterCopy, master, sizeof(master));

    pb::PostboxKeys k1{}, k1again{}, k2{};
    pb::DerivePostboxKeys(&k1, master);

    // the master is wiped in place, all 32 bytes
    bool wiped = true;
    for (uint32_t i = 0; i < 32; ++i)
        if (master[i] != 0) wiped = false;
    CHECK(wiped);

    // deterministic: same master -> identical subkeys
    pb::DerivePostboxKeys(&k1again, masterCopy);
    CHECK(memcmp(&k1, &k1again, sizeof(k1)) == 0);

    // distinct master -> distinct keys
    uint8_t master2[32] = {};
    master2[0] = 0xAA;
    pb::DerivePostboxKeys(&k2, master2);
    CHECK(memcmp(&k1, &k2, sizeof(k1)) != 0);
}

static void TestDerivePostboxKeysComposition()
{
    // Independent two-step proof of the KDF layout: ChaCha20Block itself is
    // pinned by the RFC 8439 KAT above, so recomposing the block here and
    // comparing the slices proves DerivePostboxKeys uses exactly
    // "ChaCha20 block, zero nonce, counter 0" and the documented 32/16/16 split.
    uint8_t master[32];
    for (uint32_t i = 0; i < 32; ++i) master[i] = static_cast<uint8_t>(i * 7 + 1);
    uint8_t masterCopy[32];
    memcpy(masterCopy, master, sizeof(master));

    pb::PostboxKeys keys{};
    pb::DerivePostboxKeys(&keys, master);

    const uint8_t zeroNonce[12] = {};
    uint8_t block[64] = {};
    pb::ChaCha20Block(block, masterCopy, zeroNonce, 0);

    CHECK(memcmp(keys.ChaChaKey, block, 32) == 0);
    CHECK(memcmp(keys.SipKey0, block + 32, 16) == 0);
    CHECK(memcmp(keys.SipKey1, block + 48, 16) == 0);
}

static void TestWipePostboxKeys()
{
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x33);
    const uint8_t zero[sizeof(keys)] = {};
    CHECK(memcmp(&keys, zero, sizeof(keys)) != 0);   // non-zero before the wipe
    pb::WipePostboxKeys(&keys);
    CHECK(memcmp(&keys, zero, sizeof(keys)) == 0);   // and zero after
}

// ===========================================================================
// 3. Nonce construction
// ===========================================================================

static void TestNonceConstruction()
{
    uint8_t body[12] = {};
    uint8_t header[12] = {};
    const uint64_t sessionId = 0x1122'3344'5566'7788ull;
    const uint64_t nonce64 = 0xAABB'CCDD'EEFF'0011ull;

    pb::MakeBodyNonce(body, sessionId, nonce64);
    pb::MakeHeaderNonce(header, sessionId, nonce64);

    CHECK(pb::Load32LE(body) == static_cast<uint32_t>(sessionId));
    CHECK(pb::Load64LE(body + 4) == nonce64);
    CHECK(pb::Load32LE(header) == (static_cast<uint32_t>(sessionId) ^ pb::kHeaderNonceXor));
    CHECK(pb::Load64LE(header + 4) == nonce64);
    CHECK(pb::Load32LE(body) != pb::Load32LE(header));
}

// ===========================================================================
// 4. Seal / open symmetry (header + body)
// ===========================================================================

static void TestSealOpenHeaderAndBody()
{
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x11);

    const uint64_t sessionId = 0x0123'4567'89AB'CDEFull;
    const uint64_t nonce64 = 1;

    // body round trip; wrong nonce does not restore the plaintext
    uint8_t body[0x40];
    for (uint32_t i = 0; i < sizeof(body); ++i) body[i] = static_cast<uint8_t>(i ^ 0x5A);
    uint8_t plain[sizeof(body)];
    memcpy(plain, body, sizeof(body));

    CHECK(pb::SealRequestBody(body, sizeof(body), keys, sessionId, nonce64));
    CHECK(memcmp(body, plain, sizeof(body)) != 0);
    CHECK(pb::OpenRequestBody(body, sizeof(body), keys, sessionId, nonce64));
    CHECK(memcmp(body, plain, sizeof(body)) == 0);

    // header: ONLY the 20 bytes at 0x0C..0x1F are sealed. Fill every byte so a
    // wrong cipher offset/length (e.g. sealing into the Nonce) is caught.
    uint8_t header[pb::kHeaderBytes];
    for (uint32_t i = 0; i < sizeof(header); ++i) header[i] = static_cast<uint8_t>(i * 3 + 1);
    uint8_t headerPlain[pb::kHeaderBytes];
    memcpy(headerPlain, header, sizeof(header));

    CHECK(pb::SealRequestHeader(header, keys, sessionId, nonce64));
    bool lowUnchanged = true, highUnchanged = true, cipherChanged = false;
    for (uint32_t i = 0; i < pb::kHeaderCipherOffset; ++i)
        if (header[i] != headerPlain[i]) lowUnchanged = false;
    for (uint32_t i = pb::kNonceOffset; i < sizeof(header); ++i)
        if (header[i] != headerPlain[i]) highUnchanged = false;
    for (uint32_t i = pb::kHeaderCipherOffset; i < pb::kNonceOffset; ++i)
        if (header[i] != headerPlain[i]) cipherChanged = true;
    CHECK(lowUnchanged);      // Seq/Ack/Status untouched
    CHECK(highUnchanged);     // Nonce/Mac/SessionId untouched
    CHECK(cipherChanged);     // Op/Pid/Size/Address sealed

    CHECK(pb::OpenRequestHeader(header, keys, sessionId, nonce64));
    CHECK(memcmp(header, headerPlain, sizeof(header)) == 0);
}

static void TestSealOpenWrongNonceFails()
{
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x22);

    uint8_t body[0x20];
    for (uint32_t i = 0; i < sizeof(body); ++i) body[i] = static_cast<uint8_t>(i + 1);
    uint8_t plain[sizeof(body)];
    memcpy(plain, body, sizeof(body));

    const uint64_t sessionId = 0x99;
    CHECK(pb::SealRequestBody(body, sizeof(body), keys, sessionId, 1));

    uint8_t wrong[sizeof(body)];
    memcpy(wrong, body, sizeof(body));
    CHECK(pb::OpenRequestBody(wrong, sizeof(body), keys, sessionId, 2));
    CHECK(memcmp(wrong, plain, sizeof(body)) != 0);

    // header and body nonces are domain-separated: sealing the same 20 bytes
    // under the body nonce must differ from the header-nonce ciphertext
    uint8_t h1[pb::kHeaderBytes] = {}, h2[pb::kHeaderBytes] = {};
    for (uint32_t i = 0; i < pb::kHeaderCipherBytes; ++i)
        h1[pb::kHeaderCipherOffset + i] = h2[pb::kHeaderCipherOffset + i] =
            static_cast<uint8_t>(i + 1);
    CHECK(pb::SealRequestHeader(h1, keys, sessionId, 3));
    CHECK(pb::SealRequestBody(h2 + pb::kHeaderCipherOffset, pb::kHeaderCipherBytes,
                              keys, sessionId, 3));
    CHECK(memcmp(h1 + pb::kHeaderCipherOffset, h2 + pb::kHeaderCipherOffset,
                 pb::kHeaderCipherBytes) != 0);
}

static void TestSealOpenMaxBody()
{
    // The protocol's maximum body: 0xFFC0 bytes = 1023 ChaCha blocks.
    static uint8_t body[pb::kMaxBodyBytes];
    for (uint32_t i = 0; i < pb::kMaxBodyBytes; ++i)
        body[i] = static_cast<uint8_t>(i * 13 + 7);
    static uint8_t plain[pb::kMaxBodyBytes];
    memcpy(plain, body, pb::kMaxBodyBytes);

    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x44);
    CHECK(pb::SealRequestBody(body, pb::kMaxBodyBytes, keys, 5, 6));
    CHECK(memcmp(body, plain, pb::kMaxBodyBytes) != 0);
    CHECK(pb::OpenRequestBody(body, pb::kMaxBodyBytes, keys, 5, 6));
    CHECK(memcmp(body, plain, pb::kMaxBodyBytes) == 0);

    CHECK(pb::SealRequestBody(body, 0, keys, 5, 6));   // zero-length no-op
}

static void TestResponseBodyWrappers()
{
    // The driver uses the response wrappers; make sure they are the same
    // construction as the request wrappers (same key/nonce space).
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x77);
    uint8_t body[0x20], plain[0x20];
    for (uint32_t i = 0; i < sizeof(body); ++i) body[i] = static_cast<uint8_t>(i * 5 + 1);
    memcpy(plain, body, sizeof(body));

    CHECK(pb::SealResponseBody(body, sizeof(body), keys, 0xAA, 0xBB));
    CHECK(pb::OpenRequestBody(body, sizeof(body), keys, 0xAA, 0xBB));
    CHECK(memcmp(body, plain, sizeof(body)) == 0);

    CHECK(pb::SealRequestBody(body, sizeof(body), keys, 0xAA, 0xBB));
    CHECK(pb::OpenResponseBody(body, sizeof(body), keys, 0xAA, 0xBB));
    CHECK(memcmp(body, plain, sizeof(body)) == 0);
}

// ===========================================================================
// 5. 128-bit tag helpers
// ===========================================================================

static void TestMac128Equal()
{
    uint8_t a[16], b[16];
    for (uint32_t i = 0; i < 16; ++i) { a[i] = static_cast<uint8_t>(i + 1); b[i] = a[i]; }
    CHECK(pb::Mac128Equal(a, b));

    // a comparison that ignored low bits would pass a 0x80-only flip; cover
    // every bit position of every byte.
    for (uint32_t pos = 0; pos < 16; ++pos)
    {
        for (uint8_t bit : {0x01, 0x80, 0xFF})
        {
            b[pos] ^= bit;
            CHECK(!pb::Mac128Equal(a, b));
            b[pos] ^= bit;
        }
    }
    CHECK(pb::Mac128Equal(a, b));                    // restored
}

static void TestMac128FinalWipesState()
{
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x88);
    pb::Mac128State s;
    pb::Mac128Init(&s, keys.SipKey0, keys.SipKey1);
    pb::Mac128Update(&s, "abc", 3);
    uint8_t tag[16] = {};
    pb::Mac128Final(&s, tag);
    const uint8_t zero[sizeof(s)] = {};
    CHECK(memcmp(&s, zero, sizeof(s)) == 0);         // state wiped
    bool tagNonZero = false;
    for (uint32_t i = 0; i < 16; ++i)
        if (tag[i] != 0) tagNonZero = true;
    CHECK(tagNonZero);
}

// ===========================================================================
// 6. Request MAC: independent canonical encoding, coverage, tamper
// ===========================================================================

struct RequestFixture
{
    pb::PostboxKeys Keys{};
    uint8_t Header[pb::kHeaderBytes] = {};
    uint8_t Body[0x18] = {};
    uint64_t SessionId = 0xFEED'FACE'CAFE'BEEFull;
    uint32_t Seq = 0x2222;
    uint64_t Nonce64 = 0x0123'4567'89AB'CDEFull;
};

static RequestFixture MakeRequestFixture()
{
    RequestFixture f;
    MakeKeys(&f.Keys, 0x55);
    for (uint32_t i = 0; i < sizeof(f.Body); ++i)
        f.Body[i] = static_cast<uint8_t>(i * 5 + 3);
    pb::SealRequestBody(f.Body, sizeof(f.Body), f.Keys, f.SessionId, f.Nonce64);

    pb::HeaderSetSeq(f.Header, f.Seq);
    pb::Store32LE(f.Header + offsetof(PostboxHeader, Op), pb_write);
    pb::Store32LE(f.Header + offsetof(PostboxHeader, Pid), 4321);
    pb::Store32LE(f.Header + offsetof(PostboxHeader, Size), sizeof(f.Body));
    pb::Store64LE(f.Header + offsetof(PostboxHeader, Address), 0x7000'0000'1234ull);
    pb::HeaderSetNonce64(f.Header, f.Nonce64);
    pb::HeaderSetSessionId(f.Header, f.SessionId);
    pb::SealRequestHeader(f.Header, f.Keys, f.SessionId, f.Nonce64);
    return f;
}

static void TestMacRequestCanonicalBytes()
{
    // Independently encode the canonical request input from the spec in
    // PostboxCrypto.h (u8 domain/version, u8 flags, u16 reserved, u64 session,
    // u32 seq, u64 nonce, u32 bodyLen, u32 headerLen, sealed header[20],
    // sealed body). This is the check that a field-order change in
    // MacRequestInit cannot pass.
    RequestFixture f = MakeRequestFixture();

    Canon canon;
    canon.U8(pb::kMacRequestDomainVersion);          // 0x11
    canon.U8(0);                                     // flags
    canon.U16(0);                                    // reserved
    canon.U64(f.SessionId);
    canon.U32(f.Seq);
    canon.U64(f.Nonce64);
    canon.U32(sizeof(f.Body));                       // bodyLen (pb_write)
    canon.U32(pb::kHeaderCipherBytes);               // headerLen = 20
    canon.Raw(f.Header + pb::kHeaderCipherOffset, pb::kHeaderCipherBytes);
    canon.Raw(f.Body, sizeof(f.Body));

    uint8_t expected[16];
    pb::Store64LE(expected, pb::SipHash24(f.Keys.SipKey0, canon.Bytes, canon.N));
    pb::Store64LE(expected + 8, pb::SipHash24(f.Keys.SipKey1, canon.Bytes, canon.N));

    uint8_t tag[16];
    pb::MacRequestTag(tag, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_write,
                      f.Header, f.Body, sizeof(f.Body));
    CHECK(memcmp(tag, expected, 16) == 0);

    // a read request must use bodyLen 0 in the canonical input
    Canon readCanon;
    readCanon.U8(pb::kMacRequestDomainVersion);
    readCanon.U8(0);
    readCanon.U16(0);
    readCanon.U64(f.SessionId);
    readCanon.U32(f.Seq);
    readCanon.U64(f.Nonce64);
    readCanon.U32(0);
    readCanon.U32(pb::kHeaderCipherBytes);
    readCanon.Raw(f.Header + pb::kHeaderCipherOffset, pb::kHeaderCipherBytes);
    uint8_t expectedRead[16];
    pb::Store64LE(expectedRead, pb::SipHash24(f.Keys.SipKey0, readCanon.Bytes, readCanon.N));
    pb::Store64LE(expectedRead + 8, pb::SipHash24(f.Keys.SipKey1, readCanon.Bytes, readCanon.N));
    uint8_t readTag[16];
    pb::MacRequestTag(readTag, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_read,
                      f.Header, f.Body, sizeof(f.Body));
    CHECK(memcmp(readTag, expectedRead, 16) == 0);
}

static void TestMacRequestTamperRejects()
{
    RequestFixture f = MakeRequestFixture();

    uint8_t tag[16], base[16];
    pb::MacRequestTag(base, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_write,
                      f.Header, f.Body, sizeof(f.Body));

    // tampered body ciphertext
    uint8_t body2[sizeof(f.Body)];
    memcpy(body2, f.Body, sizeof(f.Body));
    body2[3] ^= 0x01;
    pb::MacRequestTag(tag, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_write,
                      f.Header, body2, sizeof(f.Body));
    CHECK(!pb::Mac128Equal(tag, base));

    // tampered sealed header
    uint8_t header2[pb::kHeaderBytes];
    memcpy(header2, f.Header, sizeof(header2));
    header2[pb::kHeaderCipherOffset + 7] ^= 0x80;
    pb::MacRequestTag(tag, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_write,
                      header2, f.Body, sizeof(f.Body));
    CHECK(!pb::Mac128Equal(tag, base));

    // wrong session / seq / nonce
    pb::MacRequestTag(tag, f.Keys, f.SessionId + 1, f.Seq, f.Nonce64, pb_write,
                      f.Header, f.Body, sizeof(f.Body));
    CHECK(!pb::Mac128Equal(tag, base));
    pb::MacRequestTag(tag, f.Keys, f.SessionId, f.Seq + 1, f.Nonce64, pb_write,
                      f.Header, f.Body, sizeof(f.Body));
    CHECK(!pb::Mac128Equal(tag, base));
    pb::MacRequestTag(tag, f.Keys, f.SessionId, f.Seq, f.Nonce64 + 1, pb_write,
                      f.Header, f.Body, sizeof(f.Body));
    CHECK(!pb::Mac128Equal(tag, base));

    // a read op does NOT cover the body: the tag must equal the bodyLen-0
    // composition even when a *tampered* body is passed
    uint8_t readBase[16], readTampered[16];
    pb::MacRequestTag(readBase, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_read,
                      f.Header, f.Body, sizeof(f.Body));
    pb::MacRequestTag(readTampered, f.Keys, f.SessionId, f.Seq, f.Nonce64, pb_read,
                      f.Header, body2, sizeof(f.Body));
    CHECK(pb::Mac128Equal(readBase, readTampered));
    CHECK(!pb::Mac128Equal(readBase, base));         // coverage difference visible
}

// ===========================================================================
// 7. Response MAC: canonical bytes, coverage (incl. pb_nmi), domain
// ===========================================================================

static void TestMacResponseCanonicalBytes()
{
    // Independently encode the canonical response input (u8 0x21, flags,
    // reserved, u64 session, u32 seq, u32 ack, i32 status, u64 nonce,
    // u32 bodyLen, sealed body for pb_read/pb_nmi).
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x66);
    const uint64_t sessionId = 0x0BAD'F00D'0BAD'F00Dull;
    const uint32_t seq = 9, ack = 9;
    const int32_t status = 0;
    const uint64_t nonce64 = 0x42;
    uint8_t body[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    Canon canon;
    canon.U8(pb::kMacResponseDomainVersion);         // 0x21
    canon.U8(0);
    canon.U16(0);
    canon.U64(sessionId);
    canon.U32(seq);
    canon.U32(ack);
    canon.U32(static_cast<uint32_t>(status));
    canon.U64(nonce64);
    canon.U32(sizeof(body));
    canon.Raw(body, sizeof(body));

    uint8_t expected[16];
    pb::Store64LE(expected, pb::SipHash24(keys.SipKey0, canon.Bytes, canon.N));
    pb::Store64LE(expected + 8, pb::SipHash24(keys.SipKey1, canon.Bytes, canon.N));

    uint8_t tag[16];
    pb::MacResponseTag(tag, keys, sessionId, seq, ack, status, nonce64, pb_read,
                       body, sizeof(body));
    CHECK(memcmp(tag, expected, 16) == 0);

    // request and response domains differ (direction confusion fails even
    // though the canonical layouts differ structurally too)
    uint8_t header[pb::kHeaderBytes] = {};
    pb::HeaderSetSeq(header, seq);
    pb::HeaderSetSessionId(header, sessionId);
    uint8_t req[16];
    pb::MacRequestTag(req, keys, sessionId, seq, nonce64, pb_read, header, nullptr, 0);
    CHECK(!pb::Mac128Equal(req, tag));
}

static void TestMacResponseCoverage()
{
    pb::PostboxKeys keys{};
    MakeKeys(&keys, 0x66);
    const uint64_t sessionId = 0x1234;
    const uint32_t seq = 5, ack = 5;
    const int32_t status = 0;
    const uint64_t nonce64 = 0x77;
    uint8_t body[8] = {1,2,3,4,5,6,7,8};
    uint8_t body2[8] = {9,9,9,9,9,9,9,9};

    // status is covered
    uint8_t okTag[16], failTag[16];
    pb::MacResponseTag(okTag, keys, sessionId, seq, ack, status, nonce64, pb_read,
                       body, sizeof(body));
    pb::MacResponseTag(failTag, keys, sessionId, seq, ack,
                       static_cast<int32_t>(0xC000'0005u), nonce64, pb_read,
                       body, sizeof(body));
    CHECK(!pb::Mac128Equal(okTag, failTag));

    // ack is covered
    uint8_t ackTag[16];
    pb::MacResponseTag(ackTag, keys, sessionId, seq, ack + 1, status, nonce64, pb_read,
                       body, sizeof(body));
    CHECK(!pb::Mac128Equal(okTag, ackTag));

    // pb_read and pb_nmi cover the body; pb_ping does not
    uint8_t readA[16], readB[16], nmiA[16], nmiB[16], pingA[16], pingB[16];
    pb::MacResponseTag(readA, keys, sessionId, seq, ack, status, nonce64, pb_read, body, 8);
    pb::MacResponseTag(readB, keys, sessionId, seq, ack, status, nonce64, pb_read, body2, 8);
    CHECK(!pb::Mac128Equal(readA, readB));

    pb::MacResponseTag(nmiA, keys, sessionId, seq, ack, status, nonce64, pb_nmi, body, 8);
    pb::MacResponseTag(nmiB, keys, sessionId, seq, ack, status, nonce64, pb_nmi, body2, 8);
    CHECK(!pb::Mac128Equal(nmiA, nmiB));

    pb::MacResponseTag(pingA, keys, sessionId, seq, ack, status, nonce64, pb_ping, body, 8);
    pb::MacResponseTag(pingB, keys, sessionId, seq, ack, status, nonce64, pb_ping, body2, 8);
    CHECK(pb::Mac128Equal(pingA, pingB));

    // pb_nmi coverage must equal the manual composition with bodyLen 8
    uint8_t manual[16];
    pb::Mac128State m;
    pb::MacResponseInit(&m, keys, sessionId, seq, ack, status, nonce64, 8);
    pb::MacResponseBody(&m, body, 8);
    pb::Mac128Final(&m, manual);
    CHECK(memcmp(nmiA, manual, 16) == 0);
}

// ===========================================================================
// 8. Header accessors — LE round trips
// ===========================================================================

static void TestHeaderAccessors()
{
    uint8_t h[pb::kHeaderBytes] = {};

    pb::HeaderSetSeq(h, 0x0102'0304u);
    CHECK(pb::HeaderSeq(h) == 0x0102'0304u);
    CHECK(h[0] == 0x04 && h[1] == 0x03 && h[2] == 0x02 && h[3] == 0x01);

    pb::HeaderSetAck(h, 0xAABB'CCDDu);
    CHECK(pb::HeaderAck(h) == 0xAABB'CCDDu);

    pb::HeaderSetStatus(h, static_cast<int32_t>(0xC000'0005u));
    CHECK(pb::HeaderStatus(h) == static_cast<int32_t>(0xC000'0005u));
    pb::HeaderSetStatus(h, -1);
    CHECK(pb::HeaderStatus(h) == -1);

    pb::Store32LE(h + offsetof(PostboxHeader, Op), pb_write);
    CHECK(pb::HeaderOp(h) == pb_write);
    pb::Store32LE(h + offsetof(PostboxHeader, Pid), 4242);
    CHECK(pb::HeaderPid(h) == 4242);
    pb::Store32LE(h + offsetof(PostboxHeader, Size), 0x1234);
    CHECK(pb::HeaderSize(h) == 0x1234);

    pb::Store64LE(h + offsetof(PostboxHeader, Address), 0x1234'5678'9ABC'DEF0ull);
    CHECK(pb::HeaderAddress(h) == 0x1234'5678'9ABC'DEF0ull);

    pb::HeaderSetNonce64(h, 0xDEAD'BEEF'DEAD'BEEFull);
    CHECK(pb::HeaderNonce64(h) == 0xDEAD'BEEF'DEAD'BEEFull);

    pb::HeaderSetSessionId(h, 0x1111'2222'3333'4444ull);
    CHECK(pb::HeaderSessionId(h) == 0x1111'2222'3333'4444ull);

    uint8_t tag[16];
    for (uint32_t i = 0; i < 16; ++i) tag[i] = static_cast<uint8_t>(0x80 + i);
    pb::HeaderSetMac(h, tag);
    CHECK(memcmp(pb::HeaderMac(h), tag, 16) == 0);
    CHECK(pb::HeaderMac(h) == h + pb::kMacOffset);

    const uint8_t* ch = h;
    CHECK(pb::HeaderMac(ch) == ch + pb::kMacOffset);   // const overload
}

// ===========================================================================
// 9. ABI / protocol constants the PBX1 handoff depends on
// ===========================================================================

static void TestAbiContracts()
{
    CHECK(sizeof(pb::PostboxKeys) == 64);
    CHECK(sizeof(PostboxHeader) == 0x40);
    CHECK(sizeof(PostboxSectionHandoff) == 0x48);
    CHECK(sizeof(PostboxConfig) == 0x110);
    CHECK(sizeof(PostboxImageLayout) == 0xB0);
    CHECK(sizeof(PostboxSectionLayout) == 16);

    CHECK(PostboxSectionHandoffMagic == 0x31584250);   // "PBX1"
    CHECK(PostboxConfigMagic == 0x8E2B41D7);
    CHECK(PostboxLayoutMagic == 0x3C9A6F52);
    CHECK(PostboxConfigMagic != PostboxLayoutMagic);

    CHECK(offsetof(PostboxSectionHandoff, MailboxVa) == 0x10);
    CHECK(offsetof(PostboxSectionHandoff, Reserved) == 0x0C);
    CHECK(offsetof(PostboxSectionHandoff, SessionId) == 0x18);
    CHECK(offsetof(PostboxSectionHandoff, CreateTime) == 0x20);
    CHECK(offsetof(PostboxSectionHandoff, Key) == 0x28);
    CHECK(offsetof(PostboxConfig, CreateTime) == 0x38);
    CHECK(offsetof(PostboxConfig, SessionId) == 0x40);
    CHECK(offsetof(PostboxConfig, MmAllocateIndependentPages) == 0x48);
    CHECK(offsetof(PostboxConfig, MmSetPageProtection) == 0x50);
    CHECK(offsetof(PostboxConfig, Layout) == 0x58);
    CHECK(offsetof(PostboxConfig, MmFreeIndependentPages) == 0x108);

    CHECK(pb::kMacRequestDomainVersion == 0x11);
    CHECK(pb::kMacResponseDomainVersion == 0x21);
    CHECK(pb::kMacRequestDomainVersion != pb::kMacResponseDomainVersion);
}

static void TestPollDecisionRules()
{
    using V = PostboxSeqVerdict;
    const uint64_t S = 0x1234;
    const uint64_t N = 100;

    // next sequence / same sequence / far ahead / wrap
    CHECK(PostboxSequenceVerdict(1, 0, S, S, N, 0, 0) == V::Candidate);
    CHECK(PostboxSequenceVerdict(0, 0xFFFFFFFFu, S, S, N, 0, 0) == V::Candidate);
    CHECK(PostboxSequenceVerdict(2, 0, S, S, N, 0, 0) == V::Reject);
    CHECK(PostboxSequenceVerdict(0xFFFFFFFFu, 0, S, S, N, 0, 0) == V::Reject);

    // valid idle: same Seq/session/nonce and Ack == Seq
    CHECK(PostboxSequenceVerdict(0, 0, S, S, N, N, 0) == V::Idle);
    // same nonce but not acknowledged -> auth failure (nonce did not advance)
    CHECK(PostboxSequenceVerdict(0, 0, S, S, N, N, 1) == V::AuthFailure);
    // same-Seq stop candidate: nonce advanced
    CHECK(PostboxSequenceVerdict(0, 0, S, S, N + 1, N, 0) == V::Candidate);

    // wrong session or nonce <= LastNonce
    CHECK(PostboxSequenceVerdict(1, 0, S + 1, S, N, 0, 0) == V::AuthFailure);
    CHECK(PostboxSequenceVerdict(1, 0, S, S, N, N, 0) == V::AuthFailure);
    CHECK(PostboxSequenceVerdict(1, 0, S, S, N + 1, N, 0) == V::Candidate);

    // pre-MAC shape: known op, body-size rule, same-Seq only for pb_stop
    const uint32_t Stage = 0x10000;
    CHECK(PostboxRequestShapeOk(true, true, pb_ping, 0, Stage, false));
    CHECK(!PostboxRequestShapeOk(true, true, pb_ping, 4, Stage, false));
    CHECK(!PostboxRequestShapeOk(true, false, pb_read, 0, Stage, false));
    CHECK(PostboxRequestShapeOk(true, false, pb_read, 4, Stage, false));
    CHECK(PostboxRequestShapeOk(true, false, pb_write, Stage, Stage, false));
    CHECK(!PostboxRequestShapeOk(true, false, pb_write, Stage + 1, Stage, false));
    CHECK(PostboxRequestShapeOk(true, true, pb_stop, 0, Stage, true));
    CHECK(!PostboxRequestShapeOk(true, true, pb_ping, 0, Stage, true));
    CHECK(!PostboxRequestShapeOk(false, false, pb_read, 4, Stage, false));
    CHECK(PostboxRequestShapeOk(true, true, pb_nmi, 0, Stage, false));

    // post-MAC range: user VA bound, stage bound, write/header overlap
    const uint64_t Mailbox = 0x10000;
    CHECK(PostboxRequestRangeOk(pb_ping, 0, 0, Mailbox, Stage));
    CHECK(!PostboxRequestRangeOk(pb_read, 4, 0, Mailbox, Stage));
    CHECK(PostboxRequestRangeOk(pb_read, 4, 0x1000, Mailbox, Stage));
    CHECK(!PostboxRequestRangeOk(pb_read, 4, PostboxUserLimit, Mailbox, Stage));
    CHECK(!PostboxRequestRangeOk(pb_read, Stage + 1, 0x1000, Mailbox, Stage));

    // strict bound: Address + Size must stay below PostboxUserLimit
    CHECK(PostboxRequestRangeOk(pb_read, 1, PostboxUserLimit - 2, Mailbox, Stage));
    CHECK(!PostboxRequestRangeOk(pb_read, 1, PostboxUserLimit - 1, Mailbox, Stage));

    // a write overlapping the 0x40-byte header is rejected; a read is not
    CHECK(!PostboxRequestRangeOk(pb_write, 0x30, 0x10020, Mailbox, Stage));
    CHECK(PostboxRequestRangeOk(pb_read, 0x30, 0x10020, Mailbox, Stage));
    CHECK(PostboxRequestRangeOk(pb_write, 0x20, Mailbox - 0x20, Mailbox, Stage));
    CHECK(!PostboxRequestRangeOk(pb_write, 0x21, Mailbox - 0x20, Mailbox, Stage));
}

static void TestPageFlagsMergeAndBodyLengths()
{
    // Rx > RwNx > RNx; a later read-only section must not downgrade a writable
    // page, and an executable section always wins.
    CHECK(PostboxMergePageFlags(PostboxPageRNx, PostboxPageRNx) == PostboxPageRNx);
    CHECK(PostboxMergePageFlags(PostboxPageRNx, PostboxPageRwNx) == PostboxPageRwNx);
    CHECK(PostboxMergePageFlags(PostboxPageRwNx, PostboxPageRNx) == PostboxPageRwNx);
    CHECK(PostboxMergePageFlags(PostboxPageRNx, PostboxPageRx) == PostboxPageRx);
    CHECK(PostboxMergePageFlags(PostboxPageRwNx, PostboxPageRx) == PostboxPageRx);
    CHECK(PostboxMergePageFlags(PostboxPageRx, PostboxPageRwNx) == PostboxPageRx);
    CHECK(PostboxMergePageFlags(PostboxPageRx, PostboxPageRNx) == PostboxPageRx);

    // Request bodies: only pb_write carries Size.
    CHECK(PostboxRequestBodyLen(pb_write, 0x100) == 0x100);
    CHECK(PostboxRequestBodyLen(pb_read, 0x100) == 0);
    CHECK(PostboxRequestBodyLen(pb_ping, 4) == 0);
    CHECK(PostboxRequestBodyLen(pb_stop, 0) == 0);

    // Response bodies: none on failure; read -> Size; NMI -> 8; others 0.
    CHECK(PostboxResponseBodyLen(0, pb_read, 0x80) == 0x80);
    CHECK(PostboxResponseBodyLen(0, pb_nmi, 0) == sizeof(uint64_t));
    CHECK(PostboxResponseBodyLen(0, pb_ping, 4) == 0);
    CHECK(PostboxResponseBodyLen(0, pb_write, 4) == 0);
    CHECK(PostboxResponseBodyLen(0, pb_stop, 0) == 0);
    CHECK(PostboxResponseBodyLen(-1, pb_read, 0x80) == 0);
    CHECK(PostboxResponseBodyLen(static_cast<int32_t>(0xC0000005u), pb_nmi, 0) == 0);
}

static void TestProtocolConstants()
{
    // Postbox.h constants the driver and the loader both depend on.
    CHECK(PostboxBytes == 0x10000);
    CHECK(PostboxDataAt == 0x40);
    CHECK(PostboxDataMax == 0xFFC0);
    CHECK(PostboxSectionBytes == 0x1000);
    CHECK(PostboxSectionHandoffVersion == 2);
    CHECK(PostboxLayoutVersion == 1);
    CHECK(PostboxMaxSections == 8);

    CHECK(static_cast<uint32_t>(pb_ping) == 1);
    CHECK(static_cast<uint32_t>(pb_read) == 2);
    CHECK(static_cast<uint32_t>(pb_write) == 3);
    CHECK(static_cast<uint32_t>(pb_stop) == 4);
    CHECK(static_cast<uint32_t>(pb_nmi) == 5);
    CHECK(static_cast<uint32_t>(pb_nmi_probe) == 6);

    CHECK(static_cast<uint32_t>(PostboxPageRx) == 0);
    CHECK(static_cast<uint32_t>(PostboxPageRwNx) == 1);
    CHECK(static_cast<uint32_t>(PostboxPageRNx) == 2);

    CHECK(PostboxSectionStateWaiting == 0);
    CHECK(PostboxSectionStateLoaderReady == 1);
    CHECK(PostboxSectionStateKeyReady == 2);
    CHECK(PostboxSectionStateConsumed == 3);
    CHECK(PostboxSectionStatePublishing == 4);
    CHECK(PostboxSectionStateWithdrawn == 5);

    CHECK(pb::kHeaderBytes == 0x40);
    CHECK(pb::kHeaderCipherOffset == 0x0C);
    CHECK(pb::kHeaderCipherBytes == 20);
    CHECK(pb::kNonceOffset == 0x20);
    CHECK(pb::kMacOffset == 0x28);
    CHECK(pb::kMacBytes == 16);
    CHECK(pb::kSessionIdOffset == 0x38);
    CHECK(pb::kBodyOffset == 0x40);
    CHECK(pb::kMaxBodyBlocks == 1023);

    // config field offsets the loader writes and the driver reads
    CHECK(offsetof(PostboxConfig, Magic) == 0x00);
    CHECK(offsetof(PostboxConfig, Version) == 0x04);
    CHECK(offsetof(PostboxConfig, Pid) == 0x08);
    CHECK(offsetof(PostboxConfig, Reserved) == 0x0C);
    CHECK(offsetof(PostboxConfig, MailboxVa) == 0x10);
    CHECK(offsetof(PostboxConfig, Key) == 0x18);
}

// ===========================================================================
// 10. Config validation shared with the driver (PostboxConfigValid)
// ===========================================================================

static PostboxConfig MakeValidConfig()
{
    PostboxConfig cfg{};
    cfg.Magic = PostboxConfigMagic;
    cfg.Version = PostboxConfigVersion;
    cfg.Pid = 1234;
    cfg.Reserved = PostboxConfigReservedIndependent;
    cfg.MailboxVa = 0x7FF4FDD91000ull;
    for (uint32_t i = 0; i < sizeof(cfg.Key); ++i)
        cfg.Key[i] = static_cast<uint8_t>(i + 1);
    cfg.CreateTime = 0x1122334455667788ull;
    cfg.SessionId = 0x99;
    cfg.Layout.NtoskrnlBase = 0xFFFFF8012C600000ull;
    cfg.MmAllocateIndependentPages = 0x1111;
    cfg.MmSetPageProtection = 0x2222;
    cfg.MmFreeIndependentPages = 0x3333;
    return cfg;
}

static void TestPostboxConfigValid()
{
    auto IsInvalid = [](auto mutate) {
        PostboxConfig cfg = MakeValidConfig();
        mutate(cfg);
        uint32_t err = 0xFFFF;
        return !PostboxConfigValid(cfg, &err) && err == 30;
    };

    PostboxConfig cfg = MakeValidConfig();
    uint32_t err = 0xFFFF;
    CHECK(PostboxConfigValid(cfg, &err));
    CHECK(err == 0);

    // The helper is pure: PostboxStart now runs it BEFORE MemSetPreStartNtoskrnl,
    // so an invalid config must not have produced any side effect here.
    const PostboxConfig snapshot = cfg;
    CHECK(PostboxConfigValid(cfg, &err));
    CHECK(memcmp(&snapshot, &cfg, sizeof(cfg)) == 0);

    CHECK(IsInvalid([](PostboxConfig& c) { c.Magic = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.Version = PostboxConfigVersion - 1; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.Pid = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.MailboxVa = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.CreateTime = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.SessionId = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.Layout.NtoskrnlBase = 0; }));

    // Reserved bit 0 marks the independent-page image; a pool image must be
    // refused (the reaper would call MmFreeIndependentPages on it).
    CHECK(IsInvalid([](PostboxConfig& c) { c.Reserved = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.Reserved = 2; }));
    {
        PostboxConfig c = MakeValidConfig();
        c.Reserved = 3;                        // bit 0 set; other bits ignored
        CHECK(PostboxConfigValid(c, &err));
    }

    CHECK(IsInvalid([](PostboxConfig& c) { c.MailboxVa = 0x10004; }));   // unaligned
    {
        PostboxConfig c = MakeValidConfig();
        c.MailboxVa = PostboxUserLimit - PostboxBytes;   // exact edge
        CHECK(PostboxConfigValid(c, &err));
    }
    CHECK(IsInvalid([](PostboxConfig& c) {
        c.MailboxVa = PostboxUserLimit - PostboxBytes + 8;
    }));

    CHECK(IsInvalid([](PostboxConfig& c) { memset(c.Key, 0, sizeof(c.Key)); }));

    CHECK(IsInvalid([](PostboxConfig& c) { c.MmAllocateIndependentPages = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.MmSetPageProtection = 0; }));
    CHECK(IsInvalid([](PostboxConfig& c) { c.MmFreeIndependentPages = 0; }));

    // the error output is optional
    PostboxConfig ok = MakeValidConfig();
    CHECK(PostboxConfigValid(ok));
    ok.Magic = 0;
    CHECK(!PostboxConfigValid(ok));
}

// ===========================================================================
// harness
// ===========================================================================

int main()
{
    TestSipHashReferenceVector();
    TestSipHashIncremental();

    TestChaCha20BlockRfc8439();
    TestChaChaSigmaMask();
    TestChaChaBlocksFor();
    TestChaChaCounterWrap();
    TestChaChaXorWrapReject();
    TestChaChaXorSymmetry();

    TestDerivePostboxKeys();
    TestDerivePostboxKeysComposition();
    TestWipePostboxKeys();
    TestNonceConstruction();

    TestSealOpenHeaderAndBody();
    TestSealOpenWrongNonceFails();
    TestSealOpenMaxBody();
    TestResponseBodyWrappers();

    TestMac128Equal();
    TestMac128FinalWipesState();
    TestMacRequestCanonicalBytes();
    TestMacRequestTamperRejects();
    TestMacResponseCanonicalBytes();
    TestMacResponseCoverage();
    TestHeaderAccessors();
    TestAbiContracts();
    TestProtocolConstants();
    TestPageFlagsMergeAndBodyLengths();
    TestPollDecisionRules();
    TestPostboxConfigValid();

    std::printf("\n==== kf_postbox_crypto_tests: %u passed, %u failed ====\n",
                g_Pass, g_Fail);
    return g_Fail ? 1 : 0;
}
