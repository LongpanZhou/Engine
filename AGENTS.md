# Agent notes

## Commenting rules

- Write comments for the current code, not its history. Do not include task IDs,
  dates, changelogs, reviewer labels, or narration about removed/legacy/test-only
  code unless the comment defines current build behavior.
- Explain why a non-obvious choice exists and what invariant it preserves. Do not
  restate what the next line already says.
- Keep comments technically accurate. Update or delete any comment that
  contradicts the code.
- Do not leave commented-out code. Delete it; version control keeps history.
- Document ABI, layout, protocol, and offset invariants at the declaration or the
  check that enforces them, not as prose in unrelated functions.
- Use ASCII punctuation only: `-`, `->`, `...`. Do not use em dashes, arrows,
  smart quotes, or other non-ASCII display characters in code or agent notes.
- File headers describe purpose and current flow, not past changes or future
  plans.
- Test comments describe the behavior being pinned, not the bug or task that
  prompted the test.

## Kernel debugging (WinDbg MCP)

Default KDNET connection:

```text
net:port=50001,key=1.2.3.4
```

- Use this exact string with `open_kd_session` for the kernel target.
- `1.2.3.4` is the KDNET key, not a host address.
- `mcp-windbg` 1.5.1 has no persistent default-connection setting, so pass the
  string explicitly on every `open_kd_session` call.
- A live kernel session holds the target at a break. Resume with `g` or close
  the session with `resume: true` when the target should keep running.

## Lab VM snapshots

- The only permitted snapshot is **`pre-driver-tests`** on the lab VM
  (`C:\Users\27175\Downloads\Vmware\Windows 10 x64.vmx`).
- Never create another snapshot. Do not take before/after snapshots.
- To reset the guest, revert to `pre-driver-tests` and start the VM.
- See `../VM-ACCESS.md` for guest credentials and the full rule.

## Live kernel debugging - breakpoints, no dumps

- Crashes are analyzed **live** over KDNET, never from a dump. There is no
  crash-dump workflow: do not configure, collect, or analyze `MEMORY.DMP`.
- Attach with `open_kd_session` using the connection string above, install the
  breakpoint kit `mapload/scripts/kd_breakpoints.txt`, then `g`.
- Keep the session attached while a risky run executes. On a bugcheck the
  debugger stops at `nt!KeBugCheckEx` with the faulting context - run
  `!analyze -v`, `kb`, `r`, inspect, then `g`.
- Breakpoints are session-scoped. Reinstall them after every attach or reboot.
- If a crash is missed, re-run the experiment with the debugger attached.
  Never fall back to a dump.
