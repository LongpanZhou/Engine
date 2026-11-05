# Agent notes

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

## Live kernel debugging — breakpoints, no dumps

- Crashes are analyzed **live** over KDNET, never from a dump. There is no
  crash-dump workflow: do not configure, collect, or analyze `MEMORY.DMP`.
- Attach with `open_kd_session` using the connection string above, install the
  breakpoint kit `mapload/scripts/kd_breakpoints.txt`, then `g`.
- Keep the session attached while a risky run executes. On a bugcheck the
  debugger stops at `nt!KeBugCheckEx` with the faulting context — run
  `!analyze -v`, `kb`, `r`, inspect, then `g`.
- Breakpoints are session-scoped. Reinstall them after every attach or reboot.
- If a crash is missed, re-run the experiment with the debugger attached.
  Never fall back to a dump.
