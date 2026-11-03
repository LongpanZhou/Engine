// F1 Job-post: one map, one entry, N jobs, one teardown.
//
// Included by main.cpp only when POSTBOX_JOB is defined. The loader owns an
// unnamed pagefile-backed section containing a PostboxJobBatch; the driver runs
// inline in the entry thread, copies the batch to its stack, executes each job
// with MmCopyVirtualMemory, writes the result records back, and returns. There
// is no timer, DPC, work item, thread, or state page. The image is freed by the
// loader after the entry returns.
//
// TargetPid == 0 means the current (loader) process. A cross-process batch
// takes PsAcquireProcessExitSynchronization once, for the whole batch, and
// releases it after the last job. Same-process batches take no exit sync.
//
// Test-only scope: the loader owns the job section in this branch. The product
// form is a controller-owned inherited section handle; the driver ABI does not
// change for that move.
#ifdef POSTBOX_JOB

// The job path needs seven resolved routines. Copy them to the stack and zero
// the .data slots before the first copy so a T2 .data scan during the batch
// does not find the routine table (D-06/C-01). PostboxStart's normal move to
// the state page never runs in job mode.
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

static void PostboxJobTakeImports(PostboxJobImports* I)
{
    I->PsGetCurrentProcess = (FnPsGetCurrentProcess) g_PsGetCurrentProcess_Raw;
    I->PsLookupProcessByProcessId =
        (FnPsLookupProcessByProcessId) g_PsLookupProcessByProcessId_Raw;
    I->ObDereferenceObject = (FnObDereferenceObject) g_ObDereferenceObject_Raw;
    I->MmCopyVirtualMemory = (FnMmCopyVirtualMemory) g_MmCopyVirtualMemory_Raw;
    I->AcquireExitSync =
        (FnPsAcquireProcessExitSynchronization) g_PsAcquireProcessExitSynchronization_Raw;
    I->ReleaseExitSync =
        (FnPsReleaseProcessExitSynchronization) g_PsReleaseProcessExitSynchronization_Raw;
    I->CreateTime =
        (FnPsGetProcessCreateTimeQuadPart) g_PsGetProcessCreateTimeQuadPart_Raw;

    // The persistent path normally moves these into the state page; job mode
    // has no state page, so clear the raw .data slots after the stack copy.
    g_KeInitializeTimerEx_Raw = 0;
    g_KeInitializeDpc_Raw = 0;
    g_KeSetCoalescableTimer_Raw = 0;
    g_KeCancelTimer_Raw = 0;
    g_KeFlushQueuedDpcs_Raw = 0;
    g_ExQueueWorkItem_Raw = 0;
    g_PsLookupProcessByProcessId_Raw = 0;
    g_ObDereferenceObject_Raw = 0;
    g_KeDelayExecutionThread_Raw = 0;
    g_PsGetProcessCreateTimeQuadPart_Raw = 0;
    g_ExAllocatePoolWithTag_Raw = 0;
    g_ExFreePool_Raw = 0;
    g_MmCopyVirtualMemory_Raw = 0;
    g_PsGetCurrentProcess_Raw = 0;
    g_PsAcquireProcessExitSynchronization_Raw = 0;
    g_PsReleaseProcessExitSynchronization_Raw = 0;
    g_PsCreateSystemThread_Raw = 0;
    g_ZwClose_Raw = 0;
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

// Runs one batch inline in the entry thread. PASSIVE_LEVEL (DriverEntry).
bool PostboxRunJobs(const PostboxJobConfig* Config)
{
    PostboxStartFailure = 40;
    if (!Config) return false;

    // The config page is kernel memory owned by the loader. Copy it first so a
    // concurrent loader-side write cannot change the batch mid-run.
    PostboxJobConfig Cfg = *Config;
    uint32_t ConfigError = 0;
    if (!PostboxJobConfigValid(Cfg, &ConfigError))
    {
        PostboxStartFailure = ConfigError ? ConfigError : 40;
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    PostboxJobImports Imports{};
    PostboxJobTakeImports(&Imports);
    if (!Imports.PsGetCurrentProcess || !Imports.PsLookupProcessByProcessId ||
        !Imports.ObDereferenceObject || !Imports.MmCopyVirtualMemory ||
        !Imports.AcquireExitSync || !Imports.ReleaseExitSync || !Imports.CreateTime)
    {
        PostboxStartFailure = 47;
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    void* Current = Imports.PsGetCurrentProcess();
    if (!Current)
    {
        PostboxStartFailure = 47;
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    PostboxJobBatch Batch{};
    size_t HeaderDone = 0;
    const int32_t HeaderStatus = PostboxJobCopy(
        Imports, Current, Cfg.SectionVa, Current,
        (uint64_t) (uintptr_t) &Batch, sizeof(Batch), &HeaderDone);
    if (HeaderStatus < 0 || HeaderDone != sizeof(Batch))
    {
        print(ERROR("PostboxJob: cannot read batch header"));
        PostboxStartFailure = 42;
        PostboxWipe(&Batch, sizeof(Batch));
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    // Authenticate the input batch before trusting any record. The key is
    // transient: it lives in the config page and this stack copy only.
    const uint64_t BatchMac = pb::SipHash24(Cfg.Key, &Batch, sizeof(Batch));
    if (BatchMac != Cfg.Mac)
    {
        print(ERROR("PostboxJob: batch MAC mismatch"));
        PostboxStartFailure = 48;
        PostboxWipe(&Batch, sizeof(Batch));
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
    }

    uint32_t BatchError = 0;
    if (!PostboxJobBatchValid(Batch, Cfg, &BatchError))
    {
        print(ERROR("PostboxJob: invalid batch"));
        PostboxStartFailure = BatchError ? BatchError : 41;
        PostboxWipe(&Batch, sizeof(Batch));
        PostboxWipe(&Imports, sizeof(Imports));
        PostboxWipe(&Cfg, sizeof(Cfg));
        return false;
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
            PostboxStartFailure = 43;
            PostboxWipe(&Batch, sizeof(Batch));
            PostboxWipe(&Imports, sizeof(Imports));
            PostboxWipe(&Cfg, sizeof(Cfg));
            return false;
        }
        Target = Process;

        if ((uint64_t) Imports.CreateTime(Process) != Cfg.TargetCreateTime)
        {
            print(ERROR("PostboxJob: target create time mismatch"));
            Imports.ObDereferenceObject(Process);
            PostboxStartFailure = 44;
            PostboxWipe(&Batch, sizeof(Batch));
            PostboxWipe(&Imports, sizeof(Imports));
            PostboxWipe(&Cfg, sizeof(Cfg));
            return false;
        }

        Status = Imports.AcquireExitSync(Process);
        if (Status < 0)
        {
            print(ERROR("PostboxJob: exit synchronization failed"));
            Imports.ObDereferenceObject(Process);
            PostboxStartFailure = 45;
            PostboxWipe(&Batch, sizeof(Batch));
            PostboxWipe(&Imports, sizeof(Imports));
            PostboxWipe(&Cfg, sizeof(Cfg));
            return false;
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
        size_t Done = 0;
        int32_t Status;
        if (Job.Op == pb_job_read)
            Status = PostboxJobCopy(Imports, Target, Job.Address, Current, DataVa,
                                    Job.Size, &Done);
        else
            Status = PostboxJobCopy(Imports, Current, DataVa, Target, Job.Address,
                                    Job.Size, &Done);

        Job.Status = (uint32_t) Status;
        Job.Done = (uint32_t) Done;
        if (Status < 0 || Done != Job.Size) AllOk = false;
        PostboxWipe(&DataVa, sizeof(DataVa));
        PostboxWipe(&Done, sizeof(Done));
    }

    // The completion marker is written by the driver, so a ping-only batch is
    // distinguishable from the loader's input records. Results go back to the
    // same section the loader reads after the entry.
    Batch.Reserved = PostboxJobDoneMagic;
    size_t ResultDone = 0;
    const int32_t ResultStatus = PostboxJobCopy(
        Imports, Current, (uint64_t) (uintptr_t) &Batch, Current,
        Cfg.SectionVa, sizeof(Batch), &ResultDone);
    if (ResultStatus < 0 || ResultDone != sizeof(Batch))
    {
        print(ERROR("PostboxJob: cannot write results"));
        AllOk = false;
    }

    if (CrossProcess)
    {
        Imports.ReleaseExitSync(Target);
        Imports.ObDereferenceObject(Target);
    }

    if (!AllOk) PostboxStartFailure = 46;
    PostboxWipe(&Target, sizeof(Target));
    PostboxWipe(&Current, sizeof(Current));
    PostboxWipe(&Imports, sizeof(Imports));
    PostboxWipe(&Batch, sizeof(Batch));
    PostboxWipe(&Cfg, sizeof(Cfg));
    return AllOk;
}

#endif // POSTBOX_JOB
