// Job-only batch: one map, one entry, N jobs, one teardown.
//
// Included by main.cpp only when POSTBOX_JOB is defined. The controller owns an
// unnamed pagefile-backed section containing a sealed PostboxJobBatch and the
// sealed job data. The driver runs inline in the entry thread, copies the
// ciphertext batch to its stack, authenticates it, opens it, executes each job
// with MmCopyVirtualMemory, seals the results back into the section, and
// returns. There is no timer, DPC, work item, thread, or state page. The image
// is freed by the loader after the entry returns.
//
// Version 2 transport: the batch and each data region are ChaCha20-sealed, and
// the batch ciphertext is authenticated with SipHash-2-4. The 32-byte master in
// the config page is copied to the stack, the page copy and the stack copy are
// then zeroed, and only the derived key schedule survives on the transient
// entry stack (PostboxJobCrypto.h).
//
// TargetPid == 0 means the current (loader) process. A cross-process batch
// takes PsAcquireProcessExitSynchronization once, for the whole batch, and
// releases it after the last job. Same-process batches take no exit sync.
#ifdef POSTBOX_JOB

// Each data transfer goes through a kernel stack chunk, so a 64 KiB job never
// needs a pool allocation. The chunk size is a multiple of the ChaCha20 block
// size, so the byte offset stays block-aligned across chunks.
constexpr uint32_t PostboxJobChunkBytes = 0x400;

// The job path needs seven resolved routines. Copy them from the loader-owned
// config into one stack table; both the config copy and the table are wiped
// before returning, so neither remains resident after the entry. The persistent
// channel's state-page move does not run in job mode.
struct PostboxJobImports
{
    FnPsGetCurrentProcess PsGetCurrentProcess;
    FnPsLookupProcessByProcessId PsLookupProcessByProcessId;
    FnObDereferenceObject ObDereferenceObject;
    FnMmCopyVirtualMemory MmCopyVirtualMemory;
    FnPsAcquireProcessExitSynchronization AcquireExitSync;
    FnPsReleaseProcessExitSynchronization ReleaseExitSync;
    FnPsGetProcessCreateTimeQuadPart CreateTime;
};

static void PostboxJobTakeImports(const PostboxJobConfig& Cfg, PostboxJobImports* I)
{
    I->PsGetCurrentProcess = (FnPsGetCurrentProcess) Cfg.Imports[0];
    I->PsLookupProcessByProcessId = (FnPsLookupProcessByProcessId) Cfg.Imports[1];
    I->ObDereferenceObject = (FnObDereferenceObject) Cfg.Imports[2];
    I->MmCopyVirtualMemory = (FnMmCopyVirtualMemory) Cfg.Imports[3];
    I->AcquireExitSync = (FnPsAcquireProcessExitSynchronization) Cfg.Imports[4];
    I->ReleaseExitSync = (FnPsReleaseProcessExitSynchronization) Cfg.Imports[5];
    I->CreateTime = (FnPsGetProcessCreateTimeQuadPart) Cfg.Imports[6];
}

// Copy between a user VA in SourceProcess and either a user VA in TargetProcess
// or a kernel stack buffer. MmCopyVirtualMemory accepts the kernel destination
// with PreviousMode=KernelMode (the same pattern as PostboxCopy). The batch
// validator has already range-checked every user VA.
static int32_t PostboxJobCopy(const PostboxJobImports& Imports,
                              void* SourceProcess, uint64_t SourceVa,
                              void* TargetProcess, uint64_t TargetVa, size_t Size,
                              size_t* DoneOut)
{
    if (DoneOut) *DoneOut = 0;
    if (!Size) return 0;
    if (!Imports.MmCopyVirtualMemory) return (int32_t) 0xC0000001;

    size_t Done = 0;
    const int32_t Status = Imports.MmCopyVirtualMemory(
        SourceProcess, (void*) (uintptr_t) SourceVa,
        TargetProcess, (void*) (uintptr_t) TargetVa,
        Size, 0 /* KernelMode */, &Done);
    if (DoneOut) *DoneOut = Done;
    return Status;
}

// EPROCESS layout check for the job-only build. The caller passes
// PsGetCurrentProcess; the fields below are the same offsets pinned by the
// static asserts in Lib/structs.h.
static bool PostboxJobLayoutOk(void* Current)
{
    if (!Current) return false;
    const _EPROCESS* P = (_EPROCESS*) Current;
    if (!P->UniqueProcessId) return false;
    if (!P->ActiveProcessLinks.Flink || !P->ActiveProcessLinks.Blink) return false;
    if (!P->Peb) return false;
    if (!P->ImageFileName[0]) return false;
    return true;
}

// Runs one batch inline in the entry thread. PASSIVE_LEVEL (DriverEntry).
bool PostboxRunJobs(const PostboxJobConfig* Config)
{
    PostboxStartFailure = 40;
    if (!Config) return false;

    // The config page is kernel memory owned by the loader. Copy it first so a
    // concurrent loader-side write cannot change the batch mid-run.
    PostboxJobConfig Cfg = *Config;

    // The loader-owned page is writable. Erase both copies of the master on
    // every early return, not just the normal path.
    auto WipeConfigKey = [&]()
    {
        PostboxWipe(const_cast<uint8_t*>(Config->Key), sizeof(Config->Key));
        PostboxWipe(Cfg.Key, sizeof(Cfg.Key));
    };

    uint32_t ConfigError = 0;
    if (!PostboxJobConfigValid(Cfg, &ConfigError))
    {
        PostboxStartFailure = ConfigError ? ConfigError : 40;
        WipeConfigKey();
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    PostboxJobImports Imports{};
    PostboxJobTakeImports(Cfg, &Imports);

    auto FailEarly = [&](uint32_t Code) -> bool
    {
        PostboxStartFailure = Code;
        WipeConfigKey();
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    };

    if (!Imports.PsGetCurrentProcess || !Imports.PsLookupProcessByProcessId ||
        !Imports.ObDereferenceObject || !Imports.MmCopyVirtualMemory ||
        !Imports.AcquireExitSync || !Imports.ReleaseExitSync || !Imports.CreateTime)
        return FailEarly(47);

    void* Current = Imports.PsGetCurrentProcess();
    if (!Current)
        return FailEarly(47);

    if (!PostboxJobLayoutOk(Current))
        return FailEarly(49);

    // Take the master out of both config copies before touching the section.
    // The loader-owned page is writable; the stack copy is wiped immediately.
    uint8_t Master[32] = {};
    for (uint32_t i = 0; i < sizeof(Master); ++i)
        Master[i] = Cfg.Key[i];
    WipeConfigKey();

    pb::PostboxKeys Keys{};
    pb::DerivePostboxKeys(&Keys, Master);   // wipes Master

    PostboxJobBatch Batch{};
    uint8_t Chunk[PostboxJobChunkBytes] = {};

    auto Fail = [&](uint32_t Code) -> bool
    {
        PostboxStartFailure = Code;
        PostboxWipe(&Keys, sizeof(Keys));
        PostboxWipe(Master, sizeof(Master));
        PostboxWipe(Chunk, sizeof(Chunk));
        PostboxWipe(&Batch, sizeof(Batch));
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    };

    // Copy the sealed batch. Authenticate the ciphertext before opening it.
    size_t HeaderDone = 0;
    const int32_t HeaderStatus = PostboxJobCopy(
        Imports, Current, Cfg.SectionVa, Current,
        (uint64_t) (uintptr_t) &Batch, sizeof(Batch), &HeaderDone);
    if (HeaderStatus < 0 || HeaderDone != sizeof(Batch))
    {
        print(ERROR("PostboxJob: cannot read batch header"));
        return Fail(42);
    }

    if (pb::JobBatchMac(Keys, Batch) != Cfg.Mac)
    {
        print(ERROR("PostboxJob: batch MAC mismatch"));
        return Fail(48);
    }

    if (!pb::JobCryptBatch(&Batch, Keys, Cfg.Nonce, false))
        return Fail(48);

    uint32_t BatchError = 0;
    if (!PostboxJobBatchValid(Batch, Cfg, &BatchError))
    {
        print(ERROR("PostboxJob: invalid batch"));
        return Fail(BatchError ? BatchError : 41);
    }

    // Resolve the target once. TargetPid == 0 is the current process and takes
    // no reference and no exit synchronization.
    void* Target = Current;
    const bool CrossProcess = Cfg.TargetPid != 0;
    if (CrossProcess)
    {
        void* Process = nullptr;
        int32_t Status = Imports.PsLookupProcessByProcessId(
            (void*) (uintptr_t) Cfg.TargetPid, &Process);
        if (Status < 0 || !Process)
        {
            print(ERROR("PostboxJob: target process %llu not found"),
                  (unsigned long long) Cfg.TargetPid);
            return Fail(43);
        }
        Target = Process;

        if ((uint64_t) Imports.CreateTime(Process) != Cfg.TargetCreateTime)
        {
            print(ERROR("PostboxJob: target create time mismatch"));
            Imports.ObDereferenceObject(Process);
            return Fail(44);
        }

        Status = Imports.AcquireExitSync(Process);
        if (Status < 0)
        {
            print(ERROR("PostboxJob: exit synchronization failed"));
            Imports.ObDereferenceObject(Process);
            return Fail(45);
        }
    }

    bool AllOk = true;
    for (uint32_t i = 0; i < Batch.Count; ++i)
    {
        PostboxJobRecord& Job = Batch.Jobs[i];
        Job.Status = 0;
        Job.Done = 0;

        if (Job.Op == pb_job_ping)
            continue;

        uint64_t DataVa = Cfg.SectionVa + Job.DataOffset;
        size_t Total = 0;
        int32_t Status = 0;
        for (size_t Off = 0; Off < Job.Size; Off += PostboxJobChunkBytes)
        {
            const size_t Left = Job.Size - Off;
            const size_t N = Left < PostboxJobChunkBytes
                ? Left : PostboxJobChunkBytes;
            size_t Done = 0;

            if (Job.Op == pb_job_read)
            {
                // target -> chunk, seal, chunk -> section
                Status = PostboxJobCopy(Imports, Target, Job.Address + Off,
                                        Current, (uint64_t) (uintptr_t) Chunk,
                                        N, &Done);
                if (Status < 0 || Done != N) break;

                if (!pb::JobCryptData(Chunk, N, Keys, Cfg.Nonce, i, Job.Op, Off))
                {
                    Status = (int32_t) 0xC0000001;
                    break;
                }

                Status = PostboxJobCopy(Imports, Current,
                                        (uint64_t) (uintptr_t) Chunk,
                                        Current, DataVa + Off, N, &Done);
                if (Status < 0 || Done != N) break;
            }
            else
            {
                // section -> chunk, open, chunk -> target
                Status = PostboxJobCopy(Imports, Current, DataVa + Off,
                                        Current, (uint64_t) (uintptr_t) Chunk,
                                        N, &Done);
                if (Status < 0 || Done != N) break;

                if (!pb::JobCryptData(Chunk, N, Keys, Cfg.Nonce, i, Job.Op, Off))
                {
                    Status = (int32_t) 0xC0000001;
                    break;
                }

                Status = PostboxJobCopy(Imports, Current,
                                        (uint64_t) (uintptr_t) Chunk,
                                        Target, Job.Address + Off, N, &Done);
                if (Status < 0 || Done != N) break;
            }

            Total += Done;
        }

        Job.Status = (uint32_t) Status;
        Job.Done = (uint32_t) Total;
        if (Status < 0 || Total != Job.Size) AllOk = false;
        PostboxWipe(&DataVa, sizeof(DataVa));
    }

    // The completion marker and result records are sealed as one batch. The
    // controller opens it with the result-domain nonce and verifies DoneMagic.
    Batch.Reserved = PostboxJobDoneMagic;
    if (!pb::JobCryptBatch(&Batch, Keys, Cfg.Nonce, true))
    {
        AllOk = false;
    }
    else
    {
        size_t ResultDone = 0;
        const int32_t ResultStatus = PostboxJobCopy(
            Imports, Current, (uint64_t) (uintptr_t) &Batch, Current,
            Cfg.SectionVa, sizeof(Batch), &ResultDone);
        if (ResultStatus < 0 || ResultDone != sizeof(Batch))
        {
            print(ERROR("PostboxJob: cannot write results"));
            AllOk = false;
        }
    }

    if (CrossProcess)
    {
        Imports.ReleaseExitSync(Target);
        Imports.ObDereferenceObject(Target);
    }

    PostboxWipe(&Target, sizeof(Target));
    PostboxWipe(&Current, sizeof(Current));
    PostboxWipe(Chunk, sizeof(Chunk));
    PostboxWipe(&Keys, sizeof(Keys));
    PostboxWipe(&Batch, sizeof(Batch));
    PostboxWipe(&Imports, sizeof(Imports));
    PostboxWipe(&Cfg, sizeof(Cfg));
    PostboxWipe(Master, sizeof(Master));

    PostboxStartFailure = AllOk ? 0 : 46;
    return AllOk;
}

#endif // POSTBOX_JOB
