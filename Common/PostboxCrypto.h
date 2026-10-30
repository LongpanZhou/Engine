#pragma once

// PostboxCrypto.h - crypto primitives for the Postbox mailbox (AC-25 section 4.7).
//
// Header-only, freestanding-friendly C++17. No allocation, no STL containers,
// no exceptions, no RTTI. Byte strings are serialized explicitly little-endian,
// so nothing here depends on the host byte order or on unaligned loads.
//
// This file is wired into Postbox.cpp / PostboxClient.cpp / mapload (Version 3,
// PBK1 handoff, static stage); the channel is authenticated. See
// out/research/CRYPTO-PRIMITIVES.md for the call order and caveats.
//
// Construction (AC-25 4.7):
//
//   master[32] --ChaCha20 block, counter 0, zero nonce--> 64 bytes
//       chachaKey[32] | sipKey0[16] | sipKey1[16]
//
//   body nonce   = LE32((uint32_t)SessionId)           || LE64(Nonce64)
//   header nonce = LE32((uint32_t)SessionId ^ 0x80000000) || LE64(Nonce64)
//
//   header ciphertext = ChaCha20(chachaKey, header nonce, counter 0)
//                       over the 20 bytes at mailbox offset 0x0C
//                       (Op, Pid, Size, Address)
//   body ciphertext   = ChaCha20(chachaKey, body nonce, counter 0)
//                       over the body at offset 0x40
//
//   tag[16] = LE64(SipHash-2-4(sipKey0, canonical)) ||
//             LE64(SipHash-2-4(sipKey1, canonical))
//
// Encrypt-then-MAC. Encrypt the header fields and body first, then MAC the
// ciphertext. A verifier must authenticate the ciphertext before acting on any
// decrypted value. The canonical MAC input includes explicit lengths, so
// truncation is covered; it includes a request/response domain byte, so
// direction confusion fails.
//
// One integration wrinkle: Op/Size are inside the sealed header, so a verifier
// needs them to decide whether and how much body to MAC. It may decrypt the
// 20-byte header into a scratch copy solely to select coverage and length,
// bounds-check the result, verify the tag over the original ciphertext, and
// only then trust the decrypted fields. See CRYPTO-PRIMITIVES.md.
//
// Canonical request input (all integers little-endian):
//
//   u8  DomainVersion   0x11 (domain 1 = request, version 1)
//   u8  Flags           0
//   u16 Reserved        0
//   u64 SessionId
//   u32 Seq
//   u64 Nonce64
//   u32 BodyLen         0 unless Op == pb_write
//   u32 HeaderLen       20
//   u8  Header[20]      sealed bytes at mailbox 0x0C..0x1F
//   u8  Body[BodyLen]   sealed bytes (only when BodyLen != 0)
//
// Canonical response input:
//
//   u8  DomainVersion   0x21 (domain 2 = response, version 1)
//   u8  Flags           0
//   u16 Reserved        0
//   u64 SessionId
//   u32 Seq
//   u32 Ack
//   i32 Status
//   u64 Nonce64
//   u32 BodyLen         0 unless the request Op == pb_read
//   u8  Body[BodyLen]   sealed read result (only when BodyLen != 0)
//
// The two SipHash passes use independent 128-bit keys from the KDF and the
// same canonical byte string. There is no extra SipHash domain byte: direction
// separation is the DomainVersion byte in the message, and key separation is
// the KDF split. This is a two-pass 128-bit tag, not the unrelated "SipHash128"
// construction from the reference implementation.
//
// Caveats are in CRYPTO-PRIMITIVES.md. In particular: this does not stop a
// kernel AC or an in-process AC DLL, and Nonce64 must never repeat under one
// key. The channel is authenticated in the current driver (Version 3, PBK1).

#include <stddef.h>
#include <stdint.h>

#include "Postbox.h"

namespace pb
{

// ---------------------------------------------------------------------------
// Mailbox layout constants (must match Postbox.h)
// ---------------------------------------------------------------------------

constexpr uint32_t kHeaderBytes = 0x40;
constexpr uint32_t kHeaderCipherOffset = 0x0C;   // Op
constexpr uint32_t kHeaderCipherBytes = 20;      // Op, Pid, Size, Address
constexpr uint32_t kNonceOffset = 0x20;
constexpr uint32_t kMacOffset = 0x28;
constexpr uint32_t kMacBytes = 16;
constexpr uint32_t kSessionIdOffset = 0x38;      // PostboxHeader.SessionId
constexpr uint32_t kBodyOffset = 0x40;
constexpr uint32_t kMaxBodyBytes = PostboxDataMax;                 // 0xFFC0
constexpr uint32_t kMaxBodyBlocks = (kMaxBodyBytes + 63u) / 64u;   // 1023

static_assert(sizeof(PostboxHeader) == kHeaderBytes, "PostboxHeader layout changed");
static_assert(offsetof(PostboxHeader, Seq) == 0x00, "Seq offset changed");
static_assert(offsetof(PostboxHeader, Ack) == 0x04, "Ack offset changed");
static_assert(offsetof(PostboxHeader, Status) == 0x08, "Status offset changed");
static_assert(offsetof(PostboxHeader, Op) == kHeaderCipherOffset, "Op offset changed");
static_assert(offsetof(PostboxHeader, Pid) == 0x10, "Pid offset changed");
static_assert(offsetof(PostboxHeader, Size) == 0x14, "Size offset changed");
static_assert(offsetof(PostboxHeader, Address) == 0x18, "Address offset changed");
static_assert(offsetof(PostboxHeader, Nonce) == kNonceOffset, "Nonce offset changed");
static_assert(offsetof(PostboxHeader, Mac) == kMacOffset, "Mac offset changed");
static_assert(offsetof(PostboxHeader, SessionId) == kSessionIdOffset, "SessionId offset changed");
static_assert(kHeaderCipherOffset + kHeaderCipherBytes == kNonceOffset, "header/Nonce overlap");
static_assert(kMacOffset + kMacBytes == kSessionIdOffset, "Mac/SessionId overlap");
static_assert(kSessionIdOffset + 8 == kBodyOffset, "SessionId/body overlap");
static_assert(kMaxBodyBytes == PostboxBytes - PostboxDataAt, "body size changed");
static_assert(kMaxBodyBlocks <= 1024, "AC-25 4.7 limits the body to 1024 blocks");

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

inline uint32_t Load32LE(const void* p)
{
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return static_cast<uint32_t>(b[0]) |
           (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) |
           (static_cast<uint32_t>(b[3]) << 24);
}

inline uint64_t Load64LE(const void* p)
{
    const uint8_t* b = static_cast<const uint8_t*>(p);
    return static_cast<uint64_t>(b[0]) |
           (static_cast<uint64_t>(b[1]) << 8) |
           (static_cast<uint64_t>(b[2]) << 16) |
           (static_cast<uint64_t>(b[3]) << 24) |
           (static_cast<uint64_t>(b[4]) << 32) |
           (static_cast<uint64_t>(b[5]) << 40) |
           (static_cast<uint64_t>(b[6]) << 48) |
           (static_cast<uint64_t>(b[7]) << 56);
}

inline void Store32LE(void* p, uint32_t v)
{
    uint8_t* b = static_cast<uint8_t*>(p);
    b[0] = static_cast<uint8_t>(v);
    b[1] = static_cast<uint8_t>(v >> 8);
    b[2] = static_cast<uint8_t>(v >> 16);
    b[3] = static_cast<uint8_t>(v >> 24);
}

inline void Store64LE(void* p, uint64_t v)
{
    uint8_t* b = static_cast<uint8_t*>(p);
    b[0] = static_cast<uint8_t>(v);
    b[1] = static_cast<uint8_t>(v >> 8);
    b[2] = static_cast<uint8_t>(v >> 16);
    b[3] = static_cast<uint8_t>(v >> 24);
    b[4] = static_cast<uint8_t>(v >> 32);
    b[5] = static_cast<uint8_t>(v >> 40);
    b[6] = static_cast<uint8_t>(v >> 48);
    b[7] = static_cast<uint8_t>(v >> 56);
}

// Volatile writes so the compiler cannot remove a wipe of key material.
inline void SecureZero(void* p, size_t n)
{
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n-- != 0)
        *v++ = 0;
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit block counter
// ---------------------------------------------------------------------------

inline uint32_t Rotl32(uint32_t v, unsigned n)
{
    return (v << n) | (v >> (32u - n));
}

inline void ChaCha20QuarterRound(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d ^= a; d = Rotl32(d, 16);
    c += d; b ^= c; b = Rotl32(b, 12);
    a += b; d ^= a; d = Rotl32(d, 8);
    c += d; b ^= c; b = Rotl32(b, 7);
}

// Writes one 64-byte block. out must not alias key: key is read while out is
// written, so callers keep them separate.
inline void ChaCha20Block(uint8_t out[64], const uint8_t key[32],
                          const uint8_t nonce[12], uint32_t counter)
{
    uint32_t st[16];
    st[0] = 0x61707865u;
    st[1] = 0x3320646eu;
    st[2] = 0x79622d32u;
    st[3] = 0x6b206574u;
    for (uint32_t i = 0; i < 8; ++i)
        st[4 + i] = Load32LE(key + 4 * i);
    st[12] = counter;
    for (uint32_t i = 0; i < 3; ++i)
        st[13 + i] = Load32LE(nonce + 4 * i);

    uint32_t x[16];
    for (uint32_t i = 0; i < 16; ++i)
        x[i] = st[i];

    for (uint32_t i = 0; i < 10; ++i)
    {
        ChaCha20QuarterRound(x[0], x[4], x[8], x[12]);
        ChaCha20QuarterRound(x[1], x[5], x[9], x[13]);
        ChaCha20QuarterRound(x[2], x[6], x[10], x[14]);
        ChaCha20QuarterRound(x[3], x[7], x[11], x[15]);
        ChaCha20QuarterRound(x[0], x[5], x[10], x[15]);
        ChaCha20QuarterRound(x[1], x[6], x[11], x[12]);
        ChaCha20QuarterRound(x[2], x[7], x[8], x[13]);
        ChaCha20QuarterRound(x[3], x[4], x[9], x[14]);
    }

    for (uint32_t i = 0; i < 16; ++i)
        Store32LE(out + 4 * i, x[i] + st[i]);

    SecureZero(st, sizeof(st));
    SecureZero(x, sizeof(x));
}

// Number of blocks needed for len bytes; 0 for len == 0.
inline uint64_t ChaCha20BlocksFor(size_t len)
{
    return (static_cast<uint64_t>(len) + 63u) >> 6;
}

// Returns false without writing if the requested range would wrap the 32-bit
// block counter (counter + blocks > 2^32). With the protocol's 1023-block
// maximum and counter 0 this never happens.
inline bool ChaCha20Keystream(uint8_t* out, size_t len, const uint8_t key[32],
                              const uint8_t nonce[12], uint32_t counter)
{
    if (static_cast<uint64_t>(counter) + ChaCha20BlocksFor(len) > 0x100000000ull)
        return false;

    uint8_t block[64];
    size_t off = 0;
    while (len != 0)
    {
        ChaCha20Block(block, key, nonce, counter);
        const size_t n = (len < 64) ? len : 64;
        for (size_t i = 0; i < n; ++i)
            out[off + i] = block[i];
        off += n;
        len -= n;
        ++counter;
    }
    SecureZero(block, sizeof(block));
    return true;
}

// In-place XOR. Encryption and decryption are the same operation.
inline bool ChaCha20Xor(uint8_t* data, size_t len, const uint8_t key[32],
                        const uint8_t nonce[12], uint32_t counter)
{
    if (static_cast<uint64_t>(counter) + ChaCha20BlocksFor(len) > 0x100000000ull)
        return false;

    uint8_t block[64];
    size_t off = 0;
    while (len != 0)
    {
        ChaCha20Block(block, key, nonce, counter);
        const size_t n = (len < 64) ? len : 64;
        for (size_t i = 0; i < n; ++i)
            data[off + i] ^= block[i];
        off += n;
        len -= n;
        ++counter;
    }
    SecureZero(block, sizeof(block));
    return true;
}

// ---------------------------------------------------------------------------
// SipHash-2-4 (64-bit)
// ---------------------------------------------------------------------------

struct SipHashState
{
    uint64_t V0;
    uint64_t V1;
    uint64_t V2;
    uint64_t V3;
    uint64_t Total;
    uint32_t NBuf;
    uint8_t Buf[8];
};

inline uint64_t Rotl64(uint64_t v, unsigned n)
{
    return (v << n) | (v >> (64u - n));
}

inline void SipHashRound(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3)
{
    v0 += v1;
    v1 = Rotl64(v1, 13);
    v1 ^= v0;
    v0 = Rotl64(v0, 32);
    v2 += v3;
    v3 = Rotl64(v3, 16);
    v3 ^= v2;
    v0 += v3;
    v3 = Rotl64(v3, 21);
    v3 ^= v0;
    v2 += v1;
    v1 = Rotl64(v1, 17);
    v1 ^= v2;
    v2 = Rotl64(v2, 32);
}

inline void SipHashBlock(SipHashState* s, uint64_t m)
{
    s->V3 ^= m;
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    s->V0 ^= m;
}

inline void SipHashInit(SipHashState* s, const uint8_t key[16])
{
    const uint64_t k0 = Load64LE(key);
    const uint64_t k1 = Load64LE(key + 8);
    s->V0 = 0x736f6d6570736575ull ^ k0;
    s->V1 = 0x646f72616e646f6dull ^ k1;
    s->V2 = 0x6c7967656e657261ull ^ k0;
    s->V3 = 0x7465646279746573ull ^ k1;
    s->Total = 0;
    s->NBuf = 0;
    for (uint32_t i = 0; i < 8; ++i)
        s->Buf[i] = 0;
}

inline void SipHashUpdate(SipHashState* s, const void* data, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(data);
    s->Total += static_cast<uint64_t>(len);

    if (s->NBuf != 0)
    {
        while (len != 0 && s->NBuf < 8)
        {
            s->Buf[s->NBuf++] = *p++;
            --len;
        }
        if (s->NBuf == 8)
        {
            SipHashBlock(s, Load64LE(s->Buf));
            s->NBuf = 0;
        }
    }

    while (len >= 8)
    {
        SipHashBlock(s, Load64LE(p));
        p += 8;
        len -= 8;
    }

    while (len != 0)
    {
        s->Buf[s->NBuf++] = *p++;
        --len;
    }
}

// Finalizes and wipes the state. The caller must not Update after this.
inline uint64_t SipHashFinal(SipHashState* s)
{
    uint64_t b = (s->Total & 0xffull) << 56;
    for (uint32_t i = 0; i < s->NBuf; ++i)
        b |= static_cast<uint64_t>(s->Buf[i]) << (8u * i);

    s->V3 ^= b;
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    s->V0 ^= b;

    s->V2 ^= 0xff;
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    SipHashRound(s->V0, s->V1, s->V2, s->V3);
    SipHashRound(s->V0, s->V1, s->V2, s->V3);

    const uint64_t out = s->V0 ^ s->V1 ^ s->V2 ^ s->V3;
    SecureZero(s, sizeof(*s));
    return out;
}

inline uint64_t SipHash24(const uint8_t key[16], const void* data, size_t len)
{
    SipHashState s;
    SipHashInit(&s, key);
    SipHashUpdate(&s, data, len);
    return SipHashFinal(&s);
}

// ---------------------------------------------------------------------------
// 128-bit tag: two independent SipHash-2-4 passes
// ---------------------------------------------------------------------------

struct Mac128State
{
    SipHashState A;     // sipKey0
    SipHashState B;     // sipKey1
};

inline void Mac128Init(Mac128State* s, const uint8_t key0[16], const uint8_t key1[16])
{
    SipHashInit(&s->A, key0);
    SipHashInit(&s->B, key1);
}

inline void Mac128Update(Mac128State* s, const void* data, size_t len)
{
    SipHashUpdate(&s->A, data, len);
    SipHashUpdate(&s->B, data, len);
}

inline void Mac128UpdateU8(Mac128State* s, uint8_t v)
{
    Mac128Update(s, &v, 1);
}

inline void Mac128UpdateU16LE(Mac128State* s, uint16_t v)
{
    uint8_t b[2];
    b[0] = static_cast<uint8_t>(v);
    b[1] = static_cast<uint8_t>(v >> 8);
    Mac128Update(s, b, sizeof(b));
}

inline void Mac128UpdateU32LE(Mac128State* s, uint32_t v)
{
    uint8_t b[4];
    Store32LE(b, v);
    Mac128Update(s, b, sizeof(b));
}

inline void Mac128UpdateU64LE(Mac128State* s, uint64_t v)
{
    uint8_t b[8];
    Store64LE(b, v);
    Mac128Update(s, b, sizeof(b));
}

// tag = LE64(SipHash-2-4(key0, message)) || LE64(SipHash-2-4(key1, message)).
inline void Mac128Final(Mac128State* s, uint8_t tag[16])
{
    Store64LE(tag, SipHashFinal(&s->A));
    Store64LE(tag + 8, SipHashFinal(&s->B));
    SecureZero(s, sizeof(*s));
}

// Constant-time for fixed-size tags: no early exit, no data-dependent branch.
// The accumulator is volatile so the compiler cannot replace the loop with a
// short-circuiting comparison.
inline bool ConstantTimeEqual16(const uint8_t a[16], const uint8_t b[16])
{
    volatile uint32_t diff = 0;
    for (uint32_t i = 0; i < 16; ++i)
        diff = diff | static_cast<uint32_t>(a[i] ^ b[i]);
    return diff == 0;
}

inline bool Mac128Equal(const uint8_t a[16], const uint8_t b[16])
{
    return ConstantTimeEqual16(a, b);
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

struct PostboxKeys
{
    uint8_t ChaChaKey[32];
    uint8_t SipKey0[16];
    uint8_t SipKey1[16];
};

static_assert(sizeof(PostboxKeys) == 64, "PostboxKeys must be exactly one KDF block");
static_assert(offsetof(PostboxKeys, ChaChaKey) == 0, "PostboxKeys layout changed");
static_assert(offsetof(PostboxKeys, SipKey0) == 32, "PostboxKeys layout changed");
static_assert(offsetof(PostboxKeys, SipKey1) == 48, "PostboxKeys layout changed");

inline void WipePostboxKeys(PostboxKeys* keys)
{
    SecureZero(keys, sizeof(*keys));
}

// Derives the three subkeys from one ChaCha20 block with counter 0 and a zero
// nonce, with the 32-byte master as the ChaCha20 key. The master is wiped.
// This is a KDF for a uniformly random master, not a password hash.
inline void DerivePostboxKeys(PostboxKeys* out, uint8_t master[32])
{
    const uint8_t zeroNonce[12] = {0};
    uint8_t block[64];
    ChaCha20Block(block, master, zeroNonce, 0);

    for (uint32_t i = 0; i < 32; ++i)
        out->ChaChaKey[i] = block[i];
    for (uint32_t i = 0; i < 16; ++i)
        out->SipKey0[i] = block[32 + i];
    for (uint32_t i = 0; i < 16; ++i)
        out->SipKey1[i] = block[48 + i];

    SecureZero(block, sizeof(block));
    SecureZero(master, 32);
}

// ---------------------------------------------------------------------------
// Nonce construction (AC-25 4.7)
// ---------------------------------------------------------------------------

constexpr uint32_t kHeaderNonceXor = 0x80000000u;

inline void MakeBodyNonce(uint8_t out[12], uint64_t sessionId, uint64_t nonce64)
{
    Store32LE(out, static_cast<uint32_t>(sessionId));
    Store64LE(out + 4, nonce64);
}

inline void MakeHeaderNonce(uint8_t out[12], uint64_t sessionId, uint64_t nonce64)
{
    Store32LE(out, static_cast<uint32_t>(sessionId) ^ kHeaderNonceXor);
    Store64LE(out + 4, nonce64);
}

// ---------------------------------------------------------------------------
// Canonical MAC input
// ---------------------------------------------------------------------------

constexpr uint8_t kMacVersion = 1;
constexpr uint8_t kMacDomainRequest = 1;
constexpr uint8_t kMacDomainResponse = 2;
constexpr uint8_t kMacRequestDomainVersion =
    static_cast<uint8_t>((kMacDomainRequest << 4) | (kMacVersion & 0x0fu));   // 0x11
constexpr uint8_t kMacResponseDomainVersion =
    static_cast<uint8_t>((kMacDomainResponse << 4) | (kMacVersion & 0x0fu));  // 0x21

static_assert(kMacRequestDomainVersion == 0x11, "request domain/version changed");
static_assert(kMacResponseDomainVersion == 0x21, "response domain/version changed");
static_assert(kMacRequestDomainVersion != kMacResponseDomainVersion,
              "request/response domains must differ");

// Request prefix: domain/version, flags, reserved, SessionId, Seq, Nonce,
// BodyLen, HeaderLen. Followed by MacRequestHeader() and optionally
// MacRequestBody(). bodyLen must be the number of body ciphertext bytes that
// follow, 0 unless Op == pb_write.
inline void MacRequestInit(Mac128State* s, const PostboxKeys& keys,
                           uint64_t sessionId, uint32_t seq, uint64_t nonce64,
                           uint32_t bodyLen)
{
    Mac128Init(s, keys.SipKey0, keys.SipKey1);
    Mac128UpdateU8(s, kMacRequestDomainVersion);
    Mac128UpdateU8(s, 0);                       // flags
    Mac128UpdateU16LE(s, 0);                    // reserved
    Mac128UpdateU64LE(s, sessionId);
    Mac128UpdateU32LE(s, seq);
    Mac128UpdateU64LE(s, nonce64);
    Mac128UpdateU32LE(s, bodyLen);
    Mac128UpdateU32LE(s, kHeaderCipherBytes);
}

// Adds the 20 sealed header bytes from the mailbox header at 0x0C..0x1F.
inline void MacRequestHeader(Mac128State* s, const uint8_t header[kHeaderBytes])
{
    Mac128Update(s, header + kHeaderCipherOffset, kHeaderCipherBytes);
}

inline void MacRequestBody(Mac128State* s, const void* body, uint32_t bodyLen)
{
    Mac128Update(s, body, bodyLen);
}

// Response prefix: domain/version, flags, reserved, SessionId, Seq, Ack,
// Status, Nonce, BodyLen. Followed by MacResponseBody() for a read result.
inline void MacResponseInit(Mac128State* s, const PostboxKeys& keys,
                            uint64_t sessionId, uint32_t seq, uint32_t ack,
                            int32_t status, uint64_t nonce64, uint32_t bodyLen)
{
    Mac128Init(s, keys.SipKey0, keys.SipKey1);
    Mac128UpdateU8(s, kMacResponseDomainVersion);
    Mac128UpdateU8(s, 0);                       // flags
    Mac128UpdateU16LE(s, 0);                    // reserved
    Mac128UpdateU64LE(s, sessionId);
    Mac128UpdateU32LE(s, seq);
    Mac128UpdateU32LE(s, ack);
    Mac128UpdateU32LE(s, static_cast<uint32_t>(status));
    Mac128UpdateU64LE(s, nonce64);
    Mac128UpdateU32LE(s, bodyLen);
}

inline void MacResponseBody(Mac128State* s, const void* body, uint32_t bodyLen)
{
    Mac128Update(s, body, bodyLen);
}

// One-shot request tag. header is the whole 0x40 mailbox header; the 20 bytes
// at 0x0C must already be sealed (encrypt-then-MAC). body is sealed ciphertext.
// Body is covered only for Op == pb_write, per AC-25 4.7.
//
// plainOp MUST be the plaintext Op, not the byte at header+0x0C after sealing:
// that byte is ciphertext. The client knows it; a verifier that has only the
// sealed header decrypts the 20-byte header into a scratch to learn Op/Size,
// uses those values only to select the MAC coverage, and does not act on them
// until the tag verifies. See CRYPTO-PRIMITIVES.md.
inline void MacRequestTag(uint8_t tag[16], const PostboxKeys& keys,
                          uint64_t sessionId, uint32_t seq, uint64_t nonce64,
                          uint32_t plainOp, const uint8_t header[kHeaderBytes],
                          const void* body, uint32_t bodyLen)
{
    const uint32_t covered = (plainOp == pb_write) ? bodyLen : 0;
    Mac128State s;
    MacRequestInit(&s, keys, sessionId, seq, nonce64, covered);
    MacRequestHeader(&s, header);
    if (covered != 0)
        MacRequestBody(&s, body, covered);
    Mac128Final(&s, tag);
}

// One-shot response tag. requestOp is the plaintext op of the request being
// answered; the body is covered for requestOp == pb_read and pb_nmi.
// body is sealed ciphertext.
inline void MacResponseTag(uint8_t tag[16], const PostboxKeys& keys,
                           uint64_t sessionId, uint32_t seq, uint32_t ack,
                           int32_t status, uint64_t nonce64, uint32_t requestOp,
                           const void* body, uint32_t bodyLen)
{
    const uint32_t covered = (requestOp == pb_read || requestOp == pb_nmi) ? bodyLen : 0;
    Mac128State s;
    MacResponseInit(&s, keys, sessionId, seq, ack, status, nonce64, covered);
    if (covered != 0)
        MacResponseBody(&s, body, covered);
    Mac128Final(&s, tag);
}

// ---------------------------------------------------------------------------
// Seal / open helpers (ChaCha20 is symmetric, so open == seal)
// ---------------------------------------------------------------------------

inline bool CryptRequestHeader(uint8_t header[kHeaderBytes], const PostboxKeys& keys,
                               uint64_t sessionId, uint64_t nonce64)
{
    uint8_t nonce[12];
    MakeHeaderNonce(nonce, sessionId, nonce64);
    const bool ok = ChaCha20Xor(header + kHeaderCipherOffset, kHeaderCipherBytes,
                                keys.ChaChaKey, nonce, 0);
    SecureZero(nonce, sizeof(nonce));
    return ok;
}

inline bool SealRequestHeader(uint8_t header[kHeaderBytes], const PostboxKeys& keys,
                              uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestHeader(header, keys, sessionId, nonce64);
}

inline bool OpenRequestHeader(uint8_t header[kHeaderBytes], const PostboxKeys& keys,
                              uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestHeader(header, keys, sessionId, nonce64);
}

inline bool CryptRequestBody(uint8_t* body, uint32_t bodyLen, const PostboxKeys& keys,
                             uint64_t sessionId, uint64_t nonce64)
{
    uint8_t nonce[12];
    MakeBodyNonce(nonce, sessionId, nonce64);
    const bool ok = ChaCha20Xor(body, bodyLen, keys.ChaChaKey, nonce, 0);
    SecureZero(nonce, sizeof(nonce));
    return ok;
}

// A request body and a response body must never be sealed under the same
// (key, SessionId, Nonce64): that would repeat the ChaCha20 keystream. The
// current op set uses a body in only one direction per request (write request
// or read response), so the two wrappers below share the construction safely.
inline bool SealRequestBody(uint8_t* body, uint32_t bodyLen, const PostboxKeys& keys,
                            uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestBody(body, bodyLen, keys, sessionId, nonce64);
}

inline bool OpenRequestBody(uint8_t* body, uint32_t bodyLen, const PostboxKeys& keys,
                            uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestBody(body, bodyLen, keys, sessionId, nonce64);
}

inline bool SealResponseBody(uint8_t* body, uint32_t bodyLen, const PostboxKeys& keys,
                             uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestBody(body, bodyLen, keys, sessionId, nonce64);
}

inline bool OpenResponseBody(uint8_t* body, uint32_t bodyLen, const PostboxKeys& keys,
                             uint64_t sessionId, uint64_t nonce64)
{
    return CryptRequestBody(body, bodyLen, keys, sessionId, nonce64);
}

// ---------------------------------------------------------------------------
// Raw header field access (for callers that use a byte buffer, not PostboxHeader)
// ---------------------------------------------------------------------------

inline uint32_t HeaderSeq(const uint8_t* h) { return Load32LE(h + 0x00); }
inline uint32_t HeaderAck(const uint8_t* h) { return Load32LE(h + 0x04); }
inline int32_t HeaderStatus(const uint8_t* h) { return static_cast<int32_t>(Load32LE(h + 0x08)); }
inline uint32_t HeaderOp(const uint8_t* h) { return Load32LE(h + 0x0C); }
inline uint32_t HeaderPid(const uint8_t* h) { return Load32LE(h + 0x10); }
inline uint32_t HeaderSize(const uint8_t* h) { return Load32LE(h + 0x14); }
inline uint64_t HeaderAddress(const uint8_t* h) { return Load64LE(h + 0x18); }
inline uint64_t HeaderNonce64(const uint8_t* h) { return Load64LE(h + 0x20); }
inline uint64_t HeaderSessionId(const uint8_t* h) { return Load64LE(h + 0x38); }

inline uint8_t* HeaderMac(uint8_t* h) { return h + kMacOffset; }
inline const uint8_t* HeaderMac(const uint8_t* h) { return h + kMacOffset; }

inline void HeaderSetSeq(uint8_t* h, uint32_t v) { Store32LE(h + 0x00, v); }
inline void HeaderSetAck(uint8_t* h, uint32_t v) { Store32LE(h + 0x04, v); }
inline void HeaderSetStatus(uint8_t* h, int32_t v) { Store32LE(h + 0x08, static_cast<uint32_t>(v)); }
inline void HeaderSetNonce64(uint8_t* h, uint64_t v) { Store64LE(h + 0x20, v); }
inline void HeaderSetSessionId(uint8_t* h, uint64_t v) { Store64LE(h + 0x38, v); }
inline void HeaderSetMac(uint8_t* h, const uint8_t tag[16])
{
    for (uint32_t i = 0; i < 16; ++i)
        h[kMacOffset + i] = tag[i];
}

} // namespace pb
