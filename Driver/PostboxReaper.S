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
# parameter. The C worker returns here; only after its epilogue/ret do we clear
# PostboxInFlight, leaving just this wrapper's add/ret in image code when the
# reaper observes InFlight == 0. This closes the pre-epilogue free window.
    .text
    .globl PostboxWorkEntry
PostboxWorkEntry:
    subq $0x28, %rsp
    call PostboxWorkRoutine
    movl $0, PostboxInFlight(%rip)
    addq $0x28, %rsp
    ret

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
