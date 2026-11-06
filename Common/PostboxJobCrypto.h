#pragma once

// PostboxJobCrypto.h - sealed batch/data helpers for the job-only profile.
//
// The job section is the batch transport: header, PostboxJobBatch, and the
// per-job data regions. The live mailbox seals its control block and body with
// ChaCha20 and authenticates the ciphertext; the job section does the same so a
// memory scanner sees no plaintext target VAs, job sizes, or read/write data.
//
// Key schedule: the 32-byte master in the section header / job config is run
// through pb::DerivePostboxKeys (the same KDF as the mailbox). The controller
// zeros the header copy after the child maps it; the child copies the master
// into the kernel config page and zeros its stack copy; the driver derives the
// subkeys, wipes both config copies, and keeps only the stack key schedule.
//
// Nonces are domain-separated 12-byte values built from the 64-bit batch nonce:
//   request batch  -> kJobBatchRequestDomain
//   result batch   -> kJobBatchResultDomain
//   job data       -> JobDataDomain(index, op)
// Each data region uses the job's nonce and a block counter derived from the
// byte offset, so chunked copies continue one keystream without reuse.

#include <stddef.h>
#include <stdint.h>

#include "Postbox.h"
#include "PostboxCrypto.h"

namespace pb
{

// Non-ASCII domain tags; a scanner must not find a plaintext "JOB1" signature.
constexpr uint32_t kJobBatchRequestDomain = 0x93B7C4E1u;
constexpr uint32_t kJobBatchResultDomain  = 0x86A2D75Fu;
constexpr uint32_t kJobDataDomainBase     = 0xC5E30000u;

inline void MakeJobNonce(uint8_t out[12], uint32_t domain, uint64_t nonce64)
{
    Store32LE(out, domain);
    Store64LE(out + 4, nonce64);
}

inline uint32_t JobDataDomain(uint32_t index, uint32_t op)
{
    // index is 0..PostboxJobMax-1 and op is one of the small pb_job values, so
    // the low domain bits are unique per (job, direction).
    return kJobDataDomainBase ^ ((index & 0x1Fu) << 8) ^ (op & 0xFFu);
}

// MAC over the ciphertext batch. Callers encrypt first, then MAC the sealed
// bytes; a verifier checks the tag before decrypting or trusting any field.
inline uint64_t JobBatchMac(const PostboxKeys& keys, const PostboxJobBatch& ciphertext)
{
    return SipHash24(keys.SipKey0, &ciphertext, sizeof(ciphertext));
}

inline bool JobCryptBatch(PostboxJobBatch* batch, const PostboxKeys& keys,
                          uint64_t nonce64, bool result)
{
    if (!batch) return false;

    uint8_t nonce[12];
    MakeJobNonce(nonce, result ? kJobBatchResultDomain : kJobBatchRequestDomain,
                 nonce64);
    const bool ok = ChaCha20Xor(reinterpret_cast<uint8_t*>(batch), sizeof(*batch),
                                keys.ChaChaKey, nonce, 0);
    SecureZero(nonce, sizeof(nonce));
    return ok;
}

// Encrypt or decrypt one chunk of a job data region. `offset` is the byte
// offset inside that region; it must be 64-byte aligned so the block counter is
// exact. ChaCha20 is symmetric, so the same call seals and opens.
inline bool JobCryptData(uint8_t* data, size_t size, const PostboxKeys& keys,
                         uint64_t nonce64, uint32_t index, uint32_t op,
                         size_t offset)
{
    if (!data || !size) return true;
    if (offset & 63u) return false;

    const uint64_t block = offset / 64u;
    if (block > 0xFFFFFFFFull) return false;

    uint8_t nonce[12];
    MakeJobNonce(nonce, JobDataDomain(index, op), nonce64);
    const bool ok = ChaCha20Xor(data, size, keys.ChaChaKey, nonce,
                                static_cast<uint32_t>(block));
    SecureZero(nonce, sizeof(nonce));
    return ok;
}

} // namespace pb
