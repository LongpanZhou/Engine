# Postbox self-free reaper entry.
#
# PsCreateSystemThread starts this stub as the thread entry. PspSystemThreadStartup
# called it with the Windows x64 ABI, so the return address on the stack is in
# ntoskrnl, not in the image.
#
# PostboxReaperPrepare (C, PASSIVE) waits for the work routine to return, then
# frees the resident state page. The stub then loads the image range and the
# resolved MmFreeIndependentPages address and tail-jumps into it. The tail jump
# is the point: no instruction is fetched from the image after the free.
# MmFreeIndependentPages returns to PspSystemThreadStartup, which terminates the
# thread.

    .text
    .globl PostboxReaperEntry
PostboxReaperEntry:
    pushq %rbx
    subq $0x20, %rsp
    call PostboxReaperPrepare
    movq PostboxReaperBase(%rip), %rcx
    movq PostboxReaperSize(%rip), %rdx
    movq PostboxReaperFree(%rip), %rax
    addq $0x20, %rsp
    popq %rbx
    jmp *%rax
