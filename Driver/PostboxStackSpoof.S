# Generic call-site stack spoof stubs.
#
# Each stub takes the target routine as its first C argument and the target's
# arguments after it. It builds a fake stack whose return address is an nt
# `add rsp, 0x28; pop rsp; ret` gadget. The add skips the 0x20-byte shadow
# space (plus the return address), so the target may spill its arguments there
# without corrupting the restore slot. The restore slot is at fake+0x30.
#
# On return the target pops the gadget; the gadget skips the shadow space,
# `pop rsp` restores the real RSP and `ret` returns to the mapped caller. A
# stack walk inside the target sees an nt return address instead of a mapped
# return address.
#
# Stack layout at the fake RSP:
#   +0x00  nt skip-shadow gadget (target return address)
#   +0x08  shadow space (target may spill)
#   +0x28  5th target argument
#   +0x30  real RSP (restore slot; free for 0-5 argument targets)
#   +0x38  6th target argument
#   +0x40  7th target argument

    .text

    .globl PostboxSpoofCall0
PostboxSpoofCall0:
    movq %rcx, %r10                 # target
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall1
PostboxSpoofCall1:
    movq %rcx, %r10                 # target
    movq %rdx, %rcx                 # arg 1
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall2
PostboxSpoofCall2:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall3
PostboxSpoofCall3:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall4
PostboxSpoofCall4:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 0x28(%rsp), %r9            # arg 4
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall5
PostboxSpoofCall5:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 0x28(%rsp), %r9            # arg 4
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRetSkip(%rip), %rax
    movq %rax, 0(%r11)
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0x30(%r11)
    movq %rsp, 0x38(%r11)
    movq 0x30(%rsp), %rax           # arg 5
    movq %rax, 0x28(%r11)
    movq %r11, %rsp
    jmp *%r10

# 6- and 7-argument stubs keep the original pop-rsp-ret layout. They are not
# used by the worker/DPC path; PsCreateSystemThread stays a direct call.
    .globl PostboxSpoofCall6
PostboxSpoofCall6:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 0x28(%rsp), %r9            # arg 4
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0(%r11)
    movq %rsp, 8(%r11)
    movq 0x30(%rsp), %rax           # arg 5
    movq %rax, 0x28(%r11)
    movq 0x38(%rsp), %rax           # arg 6
    movq %rax, 0x30(%r11)
    movq %r11, %rsp
    jmp *%r10

    .globl PostboxSpoofCall7
PostboxSpoofCall7:
    movq %rcx, %r10
    movq %rdx, %rcx
    movq %r8, %rdx
    movq %r9, %r8
    movq 0x28(%rsp), %r9            # arg 4
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, 0(%r11)
    movq %rsp, 8(%r11)
    movq 0x30(%rsp), %rax           # arg 5
    movq %rax, 0x28(%r11)
    movq 0x38(%rsp), %rax           # arg 6
    movq %rax, 0x30(%r11)
    movq 0x40(%rsp), %rax           # arg 7
    movq %rax, 0x38(%r11)
    movq %r11, %rsp
    jmp *%r10

# MmCopyVirtualMemory-specific stub kept for the existing call site and probe.
# Same layout as PostboxSpoofCall7, but the target and gadget are dedicated
# globals so the probe can report them.
    .globl PostboxMmCopySpoof
PostboxMmCopySpoof:
    movq %rsp, %r10                 # real rsp (points at the mapped return)
    leaq -0x200(%rsp), %r11
    andq $-16, %r11                 # fake stack top
    subq $8, %r11                   # jmp entry: rsp % 16 == 8
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, g_PostboxLastGadget(%rip)
    movq %rax, 0(%r11)              # API return address = nt gadget
    movq %r10, g_PostboxLastRealRsp(%rip)
    movq %r10, 8(%r11)              # gadget restores this real rsp
    movq %r11, g_PostboxLastFakeTop(%rip)
    movq 0x28(%rsp), %rax           # Size
    movq %rax, 0x28(%r11)
    movq 0x30(%rsp), %rax           # PreviousMode
    movq %rax, 0x30(%r11)
    movq 0x38(%rsp), %rax           # Done
    movq %rax, 0x38(%r11)
    movq %r11, %rsp
    jmp *g_PostboxMmCopyTarget(%rip)

# Test-only probe target: records the return address it was entered with. When
# called through a generic spoof stub, this is the nt add-rsp gadget, not a
# mapped-image address.
    .globl PostboxStackProbeTarget
PostboxStackProbeTarget:
    movq (%rsp), %rax
    movq %rax, g_PostboxProbeTargetRet(%rip)
    ret
