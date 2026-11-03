# NMI sanitizer entry wrapper.
#
# KiProcessNMI calls this with the Windows x64 ABI:
#   RCX = Context (PostboxState*), DL = Handled
# At entry [RSP] is the nt return address. Pass the entry RSP and that return
# address as the 3rd/4th arguments to the C callback, then tail-jump so the C
# callback's ret returns directly to KiProcessNMI. No fabricated stack.

    .text
    .globl PostboxNmiSanitizeEntry
PostboxNmiSanitizeEntry:
    movq %rsp, %r8
    movq (%rsp), %r9
    jmp PostboxNmiSanitizeCallback
