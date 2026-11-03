# Shadow-stack call/return thunks for mapped-to-mapped and mapped-to-nt calls.
#
# The caller does a normal `call PostboxSpoofCallN`. The thunk saves the real
# mapped return address, the caller's post-call RSP, and the caller's R14 in
# per-worker .data arrays, overwrites the visible return slot at [RSP] with an
# nt `jmp [r14+0x83]` gadget, moves the target arguments into place, and jumps
# to the target. The target's `ret` goes to the nt gadget, which jumps to
# PostboxShadowReturn. That trampoline pops the shadow frame, restores RSP and
# R14, and jumps to the real mapped return.
#
# Register discipline:
#   - The trampoline never touches RAX: the target's return value (AL for
#     bool, EAX/RAX for integers) must survive the whole gadget chain.
#   - The thunk's scratch lives in the g_PostboxShadowScratch .data array, not
#     below RSP, so a device interrupt cannot corrupt it mid-thunk.
#
# The visible stack therefore contains only nt gadgets and data; the mapped
# return addresses live in .data, which is not part of the scanned thread
# stack.

    .text

# Per-worker return-address shadow (single worker, serialized by
# PostboxInFlight; only the intra-image calls use this thunk):
#   g_PostboxShadowRet[depth]  = real mapped return
#   g_PostboxShadowRsp[depth]  = caller RSP + 8 (post-call RSP)
#   g_PostboxShadowR14[depth]  = caller R14
#   g_PostboxShadowScratch     = {arity, A1, A2, A3} staging slots

    .globl PostboxSpoofCall0
    .globl PostboxSpoofCall1
    .globl PostboxSpoofCall2
    .globl PostboxSpoofCall3
    .globl PostboxSpoofCall4
    .globl PostboxSpoofCall5
    .globl PostboxSpoofCall6
    .globl PostboxSpoofCall7
PostboxSpoofCall0:
    movl $0, %eax
    jmp PostboxShadowCall
PostboxSpoofCall1:
    movl $1, %eax
    jmp PostboxShadowCall
PostboxSpoofCall2:
    movl $2, %eax
    jmp PostboxShadowCall
PostboxSpoofCall3:
    movl $3, %eax
    jmp PostboxShadowCall
PostboxSpoofCall4:
    movl $4, %eax
    jmp PostboxShadowCall
PostboxSpoofCall5:
    movl $5, %eax
    jmp PostboxShadowCall
PostboxSpoofCall6:
    movl $6, %eax
    jmp PostboxShadowCall
PostboxSpoofCall7:
    movl $7, %eax
    jmp PostboxShadowCall

PostboxShadowCall:
    # Entry: eax=arity, rcx=target, rdx=A1, r8=A2, r9=A3, [rsp]=real return.
    # Stage the volatile inputs in .data: rcx/rdx/r8/r9/rax become scratch for
    # the shadow save, and an interrupt cannot clobber the staging slots.
    leaq g_PostboxShadowScratch(%rip), %r11
    movl %eax, 0(%r11)              # arity
    movq %rdx, 8(%r11)              # A1
    movq %r8, 16(%r11)              # A2
    movq %r9, 24(%r11)              # A3
    movq %rcx, %r10                 # target

    # Save real return, caller RSP+8, and caller R14 at the current depth.
    movq g_PostboxShadowDepth(%rip), %rcx
    leaq g_PostboxShadowRet(%rip), %rax
    movq (%rsp), %rdx
    movq %rdx, (%rax,%rcx,8)
    leaq g_PostboxShadowRsp(%rip), %rax
    leaq 8(%rsp), %rdx
    movq %rdx, (%rax,%rcx,8)
    leaq g_PostboxShadowR14(%rip), %rax
    movq %r14, (%rax,%rcx,8)
    incq g_PostboxShadowDepth(%rip)

    # Visible return = nt jump gadget; r14 -> trampoline address slot.
    movq g_PostboxShadowJumpGadget(%rip), %rax
    movq %rax, (%rsp)
    leaq g_PostboxShadowReturn(%rip), %r14
    addq $0x7d, %r14                # [r14-0x7d] = g_PostboxShadowReturn

    # Arity-dependent stack arguments: A4 -> R9, then shift A5/A6/A7 down one
    # slot so the target sees them at RSP+0x28/0x30/0x38. RAX is free scratch.
    movl 0(%r11), %r11d             # arity (zero-extends, drops the base)
    cmpl $4, %r11d
    jb 1f
    movq 0x28(%rsp), %r9            # A4 -> target R9
1:
    cmpl $5, %r11d
    jb 2f
    movq 0x30(%rsp), %rax           # A5 -> A4 slot
    movq %rax, 0x28(%rsp)
2:
    cmpl $6, %r11d
    jb 3f
    movq 0x38(%rsp), %rax           # A6 -> A5 slot
    movq %rax, 0x30(%rsp)
3:
    cmpl $7, %r11d
    jb 4f
    movq 0x40(%rsp), %rax           # A7 -> A6 slot
    movq %rax, 0x38(%rsp)
4:
    # Restore the register arguments from the staging slots and jump.
    leaq g_PostboxShadowScratch(%rip), %r11
    movq 8(%r11), %rcx              # A1
    movq 16(%r11), %rdx             # A2
    movq 24(%r11), %r8              # A3
    jmp *%r10

# Return trampoline. Entered via the nt `jmp [r14+0x83]` gadget with RSP at the
# target's post-ret value (R+8). Pops the return-address shadow frame, restores
# RSP and R14, and jumps to the real mapped return. RAX is never touched: the
# target's return value must survive. RDX/RCx/R10 are volatile scratch.
    .globl PostboxShadowReturn
PostboxShadowReturn:
    decq g_PostboxShadowDepth(%rip)
    movq g_PostboxShadowDepth(%rip), %rcx
    leaq g_PostboxShadowRet(%rip), %rdx
    movq (%rdx,%rcx,8), %r10        # real return
    leaq g_PostboxShadowRsp(%rip), %rdx
    movq (%rdx,%rcx,8), %rsp        # caller RSP + 8
    leaq g_PostboxShadowR14(%rip), %rdx
    movq (%rdx,%rcx,8), %r14        # caller R14
    jmp *%r10

# Stable MmCopyVirtualMemory fake-stack stub. Kept separate from the shadow
# thunk so kernel APIs with complex arguments are not run on the shadow path.
    .globl PostboxMmCopySpoof
PostboxMmCopySpoof:
    movq %rsp, %r10
    leaq -0x200(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11
    movq g_PostboxPopRspRet(%rip), %rax
    movq %rax, g_PostboxLastGadget(%rip)
    movq %rax, 0(%r11)
    movq %r10, g_PostboxLastRealRsp(%rip)
    movq %r10, 8(%r11)
    movq %r11, g_PostboxLastFakeTop(%rip)
    movq 0x28(%rsp), %rax
    movq %rax, 0x28(%r11)
    movq 0x30(%rsp), %rax
    movq %rax, 0x30(%r11)
    movq 0x38(%rsp), %rax
    movq %rax, 0x38(%r11)
    movq %r11, %rsp
    jmp *g_PostboxMmCopyTarget(%rip)

# Test-only probe target: records the return address it was entered with. When
# called through the shadow thunk, this is the nt jump gadget.
    .globl PostboxStackProbeTarget
PostboxStackProbeTarget:
    movq (%rsp), %rax
    movq %rax, g_PostboxProbeTargetRet(%rip)
    ret
