# Postbox NMI gate: entered directly from the constructed IDT vector 2.
#
# The CPU has already pushed the interrupted context (RIP/CS/RFLAGS and, on a
# privilege change, RSP/SS). Save the general registers, call the C dispatcher,
# then either:
#   - consume the NMI (self-test) and iretq, or
#   - restore the saved registers and jump to the Windows NMI handler with the
#     original trap frame still at the top of the stack.
#
# The jump is memory-indirect so no register is clobbered on the chain path.
# DF is cleared for the C ABI; the trap frame's RFLAGS (and therefore the
# interrupted context's DF) is restored by iretq or by the Windows handler.

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
    movq %rsp, %rbp
    movq %rsp, %rcx
    andq $-16, %rsp
    subq $0x20, %rsp
    call PostboxNmiDispatch
    movq %rbp, %rsp

    testb %al, %al
    jne 1f

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

1:
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
