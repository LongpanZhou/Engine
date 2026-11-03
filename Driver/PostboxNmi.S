# Postbox NMI gate: entered directly from the constructed IDT vector 2.
#
# The CPU has already pushed the interrupted context (RIP/CS/RFLAGS and, on a
# privilege change, RSP/SS) on the NMI stack. The stub saves all 15 GPRs below
# the entry RSP, updates the diagnostic counters with lock-prefixed ops, then:
#   - consumes a self-test NMI and iretq's, or
#   - restores the saved registers and jumps to the Windows NMI handler with the
#     original trap frame still at the top of the stack.
#
# No C call and no stack switch: every write is either below the entry RSP or a
# RIP-relative global, so the interrupted context and its trap frame cannot be
# touched. The stub executes no XMM/FP instructions.
#
# After the 15 pushes: [rsp+0x78] = interrupted RIP, [rsp+0x80] = interrupted CS.
# PostboxNmiInFlight / PostboxNmiSelfTestPending are 32-bit longs; the counters
# and saved RIP/CS are 64-bit.

    .text
    .globl PostboxNmiStub
PostboxNmiStub:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    cld
    lock incl PostboxNmiInFlight(%rip)
    lock incq PostboxNmiTicks(%rip)
    movq 0x78(%rsp), %rax
    movq %rax, PostboxNmiLastRip(%rip)
    movq 0x80(%rsp), %rax
    movq %rax, PostboxNmiLastCs(%rip)

    # Consume a pending self-test NMI. xchg with memory is implicitly locked.
    xorl %eax, %eax
    xchgl %eax, PostboxNmiSelfTestPending(%rip)
    testl %eax, %eax
    jz 2f

    lock incq PostboxNmiHandled(%rip)
    movq 0x78(%rsp), %rax
    movq %rax, PostboxNmiLastHandledRip(%rip)
    lock decl PostboxNmiInFlight(%rip)

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq

2:
    # Chain to the Windows NMI handler with the original trap frame intact.
    lock decl PostboxNmiInFlight(%rip)

    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    jmp *PostboxOriginalNmiHandler(%rip)
