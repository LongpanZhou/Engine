# Postbox self-free reaper entry.
#
# PsCreateSystemThread starts this stub as the thread entry. PspSystemThreadStartup
# called it with the Windows x64 ABI, so the return address on the stack is in
# ntoskrnl, not in the image. RCX is the StartContext: the PostboxState page.
#
# PostboxReaperPrepare (C, PASSIVE) waits for the work routine to return, then
# fills a three-qword plan (RawBase, AllocSize, MmFreeIndependentPages) and frees
# the state page. The stub then tail-jumps to MmFreeIndependentPages. The tail
# jump is the point: no instruction is fetched from the image after the free.
# MmFreeIndependentPages returns to PspSystemThreadStartup, which terminates the
# thread.
#
# If PostboxReaperPrepare returns 0 (the worker is still in flight, or another
# teardown owns the page), the stub returns without freeing the image. The image
# and state page leak rather than being freed under a stalled worker.

# Worker entry wrapper. ExpWorkerThread calls this with RCX = the work item
# parameter. The C worker is entered through an nt `pop rsp; ret` gadget so the
# return address on its stack is an nt address, not image+offset. The epilogue
# restores the original stack, clears PostboxInFlight after the C worker's
# epilogue/ret, and returns to ExpWorkerThread. This keeps the pre-epilogue free
# window closed and removes the mapped worker return address from the stack.
    .text
    .globl PostboxWorkEntry
PostboxWorkEntry:
#ifdef STACK_SPOOF
    movq g_PostboxPopRspRetSkip(%rip), %rax
    testq %rax, %rax
    jz 1f
    pushq %r12
    movq %rsp, %r12                 # [r12] = saved r12, [r12+8] = nt return
    leaq -0x60(%r12), %rsp
    andq $-16, %rsp
    subq $8, %rsp                   # C entry rsp % 16 == 8
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
    movl $0, PostboxInFlight(%rip)
    addq $0x28, %rsp
    ret

PostboxWorkEpilogue:
    movq %r12, %rsp
    popq %r12
    movl $0, PostboxInFlight(%rip)
    ret
#else
    subq $0x28, %rsp
    call PostboxWorkRoutine
    movl $0, PostboxInFlight(%rip)
    addq $0x28, %rsp
    ret
#endif

    .text
    .globl PostboxReaperEntry
PostboxReaperEntry:
    pushq %rbx
    subq $0x40, %rsp
    movq %rcx, %rbx                 # StartContext = PostboxState*
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
