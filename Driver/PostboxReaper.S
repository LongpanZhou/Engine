# Postbox self-free reaper entry.
#
# The reaper runs on the worker's terminal path: PostboxWorkEpilogue clears
# PostboxInFlight, sees PostboxTeardownPending, loads PostboxStatePtr into RCX,
# and jumps here instead of returning to ExpWorkerThread. The return address on
# the stack is still the ExpWorkerThread call site, so the final tail jump to
# MmFreeIndependentPages returns to nt, not to the freed image.
#
# PostboxReaperPrepare (C, PASSIVE) waits for any remaining worker references,
# fills a three-qword plan (RawBase, AllocSize, MmFreeIndependentPages), and
# frees the state page. The stub then tail-jumps to MmFreeIndependentPages.
#
# If PostboxReaperPrepare returns 0 (the worker is still in flight, or another
# teardown owns the page), the stub returns to ExpWorkerThread without freeing
# the image. The image and state page leak rather than being freed under a
# stalled worker.

# Worker entry wrapper. ExpWorkerThread calls this with RCX = the work item
# parameter. The C worker is entered through an nt `pop rsp; ret` gadget so the
# return address on its stack is an nt address, not image+offset. The epilogue
# restores the original stack, clears PostboxInFlight after the C worker's
# epilogue/ret, and returns to ExpWorkerThread. This keeps the pre-epilogue free
# window closed and removes the mapped worker return address from the stack.
    .text
    .globl PostboxWorkEntry
PostboxWorkEntry:
    # The nt DPC queues the item; mark in-flight here before any mapped work so
    # the reaper cannot free the page under a just-started worker. The epilogue
    # clears it.
    movl $1, PostboxInFlight(%rip)
    # Keep kernel APCs disabled for the whole mapped work item. Detector APCs
    # stay queued until PostboxApcsNeutralizeAndEnable patches and releases
    # them in the epilogue.
    subq $8, %rsp
    call PostboxApcsDisable
    addq $8, %rsp
#ifdef STACK_SPOOF
    movq g_PostboxPopRspRetSkip(%rip), %rax
    testq %rax, %rax
    jz 1f
    pushq %r12
    movq %rsp, %r12                 # [r12] = saved r12, [r12+8] = nt return
    movq g_PostboxShadowJumpGadget(%rip), %rax
    testq %rax, %rax
    jz 2f
    movl $1, g_PostboxShadowActive(%rip)
2:
    leaq -0x60(%r12), %rsp
    andq $-16, %rsp
    subq $8, %rsp                   # C entry rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%rsp)              # C return = add-rsp-0x28; ret
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%rsp)           # add-ret target = pop rsp; ret
    leaq 0x40(%rsp), %rax
    movq %rax, 0x38(%rsp)           # pop rsp -> epilogue slot
    leaq PostboxWorkEpilogue(%rip), %rax
    movq %rax, 0x40(%rsp)           # epilogue address
    jmp PostboxWorkRoutine
1:
    subq $0x28, %rsp
    call PostboxWorkRoutine
    call PostboxApcsNeutralizeAndEnable
    call PostboxDrainThreadApcs
    movl $0, PostboxInFlight(%rip)
    addq $0x28, %rsp
    jmp PostboxWorkTail

PostboxWorkEpilogue:
    movl $0, g_PostboxShadowActive(%rip)
    movq %r12, %rsp
    popq %r12
    subq $8, %rsp
    call PostboxApcsNeutralizeAndEnable
    call PostboxDrainThreadApcs
    addq $8, %rsp
    movl $0, PostboxInFlight(%rip)
    jmp PostboxWorkTail
#else
    subq $0x28, %rsp
    call PostboxWorkRoutine
    call PostboxApcsNeutralizeAndEnable
    call PostboxDrainThreadApcs
    movl $0, PostboxInFlight(%rip)
    addq $0x28, %rsp
#endif
# Shared terminal path: PostboxInFlight is clear and the caller's stack is
# restored. Tail-jump into the reaper when the state page is still resident.
PostboxWorkTail:
    movq PostboxStatePtr(%rip), %rax
    testq %rax, %rax
    jz 3f
    cmpq $0, 0x1028(%rax)
    jne 3f
    cmpl $0, PostboxTeardownPending(%rip)
    je 3f
    movq PostboxStatePtr(%rip), %rcx
    testq %rcx, %rcx
    jz 3f
    jmp PostboxReaperEntry
3:
    ret

    .text
    # Exact-entry start path. KiUmsRestoreUch with Count=32 leaves IF=0 and
    # RSP = InitialStack-0x20. The copied qwords are, from RSP upward:
    #   [rsp]    = EventThread (unused)
    #   [rsp+8]  = EventEntry  = exact-entry nt ret thunk
    #   [rsp+16] = Copy[0]     = PsTerminateSystemThread
    #   [rsp+24] = Copy[1]
    # Shift up 8 for the normal start ABI. The event reaper is entered at RSP
    # 8 mod 16 and enters MmFreeIndependentPages with RSP = base-0x28, so
    # MmFree's 0x20-byte shadow spill only touches EventThread/Copy[1]. The
    # exact-entry skip thunk then steps over that shadow space and pops the
    # ret thunk and PsTerminateSystemThread with 8-mod-16 alignment.
    .globl PostboxEventStackEntry
PostboxEventStackEntry:
    sti
    addq $8, %rsp
    movl $1, PostboxInFlight(%rip)
    subq $0x28, %rsp
    call PostboxEventLoop
    addq $0x28, %rsp
    movl $0, PostboxInFlight(%rip)
    movq PostboxStatePtr(%rip), %rcx
    testq %rcx, %rcx
    jz 1f
    jmp PostboxEventReaperEntry
1:
    ret

    .text
    .globl PostboxEventThreadEntry
PostboxEventThreadEntry:
    movl $1, PostboxInFlight(%rip)
    subq $0x28, %rsp
    call PostboxEventLoop
    addq $0x28, %rsp
    movl $0, PostboxInFlight(%rip)
    movq PostboxStatePtr(%rip), %rcx
    testq %rcx, %rcx
    jz 1f
    jmp PostboxReaperEntry
1:
    ret

    .text
    .globl PostboxReaperEntry
PostboxReaperEntry:
    pushq %rbx
    subq $0x40, %rsp
    movq %rcx, %rbx                 # State from PostboxStatePtr (inline path)
    leaq 0x20(%rsp), %rdx           # PostboxReaperPlan on this thread's stack
    movq %rbx, %rcx
    call PostboxReaperPrepare
    testq %rax, %rax
    jz 1f

    movq 0x20(%rsp), %rcx           # RawBase
    movq 0x28(%rsp), %rdx           # AllocSize
    movq 0x30(%rsp), %rax           # MmFreeIndependentPages
    addq $0x40, %rsp
    popq %rbx
    jmp *%rax

1:
    addq $0x40, %rsp
    popq %rbx
    ret

    .text
    # Exact-entry event terminal. Entered from PostboxEventStackEntry with
    # RSP = base+8, where [base+8] is the exact-entry nt ret thunk and
    # [base+16] is PsTerminateSystemThread. On success, enter MmFree with
    # RSP = base-0x28 and an exact-entry `add rsp,0x28; ret` in [base-0x28].
    # MmFree spills into [base-0x20, base), below the terminal copy; the skip
    # thunk then pops the ret thunk and PsTerminate with correct alignment.
    # On failure, return through [base+8] so the thread still terminates.
    .globl PostboxEventReaperEntry
PostboxEventReaperEntry:
    pushq %rbx
    subq $0x40, %rsp
    movq %rcx, %rbx
    leaq 0x20(%rsp), %rdx
    movq %rbx, %rcx
    call PostboxReaperPrepare
    testq %rax, %rax
    jz 1f

    movq 0x20(%rsp), %rcx           # RawBase
    movq 0x28(%rsp), %rdx           # AllocSize
    movq 0x30(%rsp), %rax           # MmFreeIndependentPages
    addq $0x40, %rsp
    popq %rbx                       # RSP = base+8
    movq g_PostboxTerminalSkip(%rip), %r10
    movq %r10, -0x30(%rsp)          # [base-0x28] = skip thunk
    subq $0x30, %rsp                # RSP = base-0x28 (8 mod 16)
    jmp *%rax

1:
    addq $0x40, %rsp
    popq %rbx
    ret
