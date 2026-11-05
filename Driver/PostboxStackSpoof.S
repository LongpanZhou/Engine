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

# APC-stackwalk clean wait. The caller (PostboxThreadLoop) calls this with the
# Windows x64 ABI: rcx = target (KeDelayExecutionThread), rdx = Alertable,
# r8 = WaitMode, r9 = Interval. The target runs on a fake stack below the
# caller's RSP; its return address is an nt `pop rsp; ret` gadget and the real
# RSP lives on the fake stack, not in a global. While the target blocks, a
# stack walk sees the nt gadget and the fake frame, not the mapped return slot
# of the caller.
    .globl PostboxCleanWait
PostboxCleanWait:
    # Caller convention: rcx = target, rdx = Alertable, r8 = WaitMode,
    # r9 = Interval. KeDelayExecutionThread wants rcx = WaitMode,
    # rdx = Alertable, r8 = Interval. Save the target and shuffle the ABI
    # arguments before entering the target; otherwise r8 is 0/1 and the
    # target dereferences it as the Interval pointer.
    movq %rcx, %rax                 # target
    movq %r8, %rcx                  # WaitMode -> RCX
    movq %r9, %r8                   # Interval -> R8
    movq %rsp, %r10                 # real RSP (points at caller return slot)
    leaq -0x100(%rsp), %r11
    andq $-16, %r11
    subq $8, %r11                   # fake RSP, 16-byte aligned

    # Shadow-space-safe chain: the target returns with RSP = fake+8, then
    # `add rsp,0x28; ret` lands on fake+0x30 and pops the `pop rsp; ret` slot
    # there. That ret leaves RSP = fake+0x38, and pop rsp loads the real RSP
    # from fake+0x38. The chain slot must be 0x30, not 0x28: the 0x28 add is
    # applied after the target's return slot has already been popped. A callee
    # spilling its register arguments at fake+8..0x27 cannot corrupt it.
    movq g_PostboxPopRspRetSkip(%rip), %r9
    testq %r9, %r9
    jz 2f
    movq %r9, 0(%r11)               # target return = add rsp,0x28; ret
    movq g_PostboxPopRspRet(%rip), %r9
    testq %r9, %r9
    jz 2f
    movq %r9, 0x30(%r11)            # return chain = pop rsp; ret
    movq %r10, 0x38(%r11)           # pop rsp loads the real RSP
    movq %r11, %rsp
    jmp *%rax
2:
    # Legacy fallback if the skip gadget is unavailable.
    movq g_PostboxPopRspRet(%rip), %r9
    testq %r9, %r9
    jz 3f
    movq %r9, 0(%r11)
    movq %r10, 8(%r11)
    movq %r11, %rsp
    jmp *%rax
3:
    jmp *%rax

# APC-stackwalk thread loop. The mapped work is a step function that returns
# 1 to continue or 0 to stop. APCs are disabled while the step runs, so a
# detector cannot capture its mapped frames. The wait is called directly from
# this stub through PostboxCleanWait; there is no C wrapper frame left on the
# stack while the target blocks.
#
# Context (all qwords):
#   0x00 State
#   0x08 Step
#   0x10 WaitTarget
#   0x18 WaitInterval (LARGE_INTEGER, 100 ns units)
#   0x20 EnterCritical
#   0x28 LeaveCritical
    .globl PostboxThreadLoop
PostboxThreadLoop:
    pushq %rbx
    pushq %r12
    pushq %r13
    subq $0x30, %rsp                # 3 pushes + 0x30 keeps calls 16-byte aligned
    movq %rcx, %rbx
    movq 0x00(%rbx), %r12
    movq 0x08(%rbx), %r13

    # Keep kernel APCs disabled for the whole loop: both the mapped step and
    # the mapped wait run with APCs off, so a detector APC stays queued instead
    # of walking this stack. The neutralizer below redirects the detector's
    # queued KAPC KernelRoutine before the region is left.
    movq 0x20(%rbx), %rax
    testq %rax, %rax
    jz 1f
    call *%rax
1:
    movq %r12, %rcx
    call *%r13
    testl %eax, %eax
    jz 9f

    # Neutralize any detector APC queued during the step, then wait with APCs
    # still disabled. The wait timer expires normally.
    call PostboxNeutralizeDetectorApcs
    leaq 0x18(%rbx), %rcx
    call PostboxSpoofedThreadWait
    jmp 1b

9:
    # Neutralize the last pending detector APC(s), then balance the critical
    # region. Leaving delivers the patched APCs; the neutralizer frees each one
    # without capturing this thread's mapped stack. The APC-disable count must
    # reach zero or PspExitThread bugchecks 0x20 (Arg1=0, Arg2=0xFFFF).
    call PostboxNeutralizeDetectorApcs
    movq 0x28(%rbx), %rax
    testq %rax, %rax
    jz 8f
    call *%rax
8:
    # Drain any remaining (non-detector) kernel APCs before thread exit.
    call PostboxDrainThreadApcs
    addq $0x30, %rsp
    popq %r13
    popq %r12
    popq %rbx
    ret

# Test-only probe target: records the return address it was entered with. When
# called through the shadow thunk, this is the nt jump gadget.
    .globl PostboxStackProbeTarget
PostboxStackProbeTarget:
    movq (%rsp), %rax
    movq %rax, g_PostboxProbeTargetRet(%rip)
    ret
