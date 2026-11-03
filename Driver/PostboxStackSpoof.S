# Call-site stack spoof for MmCopyVirtualMemory.
#
# Microsoft x64 ABI at entry:
#   rcx, rdx, r8, r9 = args 1-4
#   [rsp+0x28] = arg 5 (Size), [rsp+0x30] = arg 6 (PreviousMode),
#   [rsp+0x38] = arg 7 (Done)
#
# Build a fake stack below the current RSP. Its return address is an nt
# `pop rsp; ret` gadget; the next qword is the real RSP. The API returns to the
# gadget, which restores the real RSP and returns to the mapped caller. The
# mapped caller's return address is never the API's return address.

    .text
    .globl PostboxMmCopySpoof
PostboxMmCopySpoof:
    movq %rsp, %r10                 # real rsp (points at the mapped return)
    leaq -0x200(%rsp), %r11
    andq $-16, %r11                 # fake stack top
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0(%r11)              # API return address = nt gadget
    movq %r10, 8(%r11)              # gadget restores this real rsp
    movq 0x28(%rsp), %rax           # Size
    movq %rax, 0x28(%r11)
    movq 0x30(%rsp), %rax           # PreviousMode
    movq %rax, 0x30(%r11)
    movq 0x38(%rsp), %rax           # Done
    movq %rax, 0x38(%r11)
    movq %r11, %rsp
    jmp *g_PostboxMmCopyTarget(%rip)
