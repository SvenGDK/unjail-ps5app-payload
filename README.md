# unjail-ps5app-payload

A persistent PS5 daemon payload. On launch it self-elevates, caches the kernel root vnode, and
opens a TCP listener on `127.0.0.1:9069`. For every accepted connection it reads a fixed
2576-byte request, promotes the caller's process (credentials, capabilities, and filesystem
view), and returns the outcome in a fixed-size reply. The daemon stays running until the
console reboots.

## When to send it

Send this payload once, before launching any homebrew application that needs read/write
access outside its per-title sandbox.

The daemon runs inside the host process the loader chose. Only that host has the
credential set and the pipe primitive that let it write another process's ucred,
capability bitmasks, and `fd_rdir` / `fd_jdir` pointers, so the daemon is the only path
an application module has to reach the extended view at run time.

## Supported firmwares

The daemon reads its kernel offsets from the CRT-embedded per-firmware table at startup.
Coverage:

| Major | Root-vnode offset | Daemon behaviour |
|---|---|---|
| 1.00 - 10.60 | Verified | Fully supported. Startup completes, listener opens, promotion requests succeed. |
| 11.00 and later | Not yet verified | Startup aborts: `PayloadKernel.GetRootVnode()` returns zero, the daemon logs `unjail: rootvnode read failed` and exits with code -1 before the listener binds. |

Verified end-to-end on device: firmware 10.01. On any other supported major the daemon
runs the same code path; the offsets that vary between majors resolve through the CRT
table without a rebuild.

The structure field offsets the daemon uses through the CRT accessors
(`cr_uid`, `cr_ruid`, `cr_svuid`, `cr_ngroups`, `cr_rgid`, `cr_sceAuthID`, `cr_sceCaps`,
`cr_sceAttrs`, `fd_rdir`, `fd_jdir`) are firmware-invariant on every supported major, so
the same daemon binary is correct across the whole covered range.

## Startup sequence

The daemon runs the following steps once, in order. Every step emits a klog line, and
every failure sends a user-visible kernel notification with the same string:

| Step | Klog | On failure |
|---|---|---|
| 1 | `unjail: daemon start` | - |
| 2 | `unjail: args ok` | `unjail: no payload args` -> exit -1 |
| 3 | `unjail: getpid ok` | `unjail: getpid failed` -> exit -1 |
| 4 | `unjail: self raised` | - |
| 5 | `unjail: authid set` | - |
| 6 | `unjail: rootvnode cached` | `unjail: rootvnode read failed` -> exit -1 |
| 7 | `unjail: daemon ready, entering accept loop` (also as a system notification) | - |

The self-elevation at steps 4 and 5 uses the same eleven-field promotion the daemon
applies to callers, plus an authorization-id write. Without it the daemon's own kernel
writes would fail the authorization check on the second call.

## Accept loop

The listener uses `AF_INET` / `SOCK_STREAM` with `SO_REUSEADDR` and a backlog of two.
For every accepted connection the daemon:

1. Reads until it has 2576 bytes or the peer closes.
2. Clears the reply buffer.
3. If the read produced at least 16 bytes and the request header validates, applies the
   promotion; otherwise writes `-1` into the outcome slot.
4. Writes the whole reply buffer back to the client and closes the connection.

The request header validation checks three fields:

| Offset | Field | Required value |
|---|---|---|
| `+0x00` | Magic | `0xDEADBEEF` |
| `+0x04` | Command | `5` |
| `+0x08` | Pid | greater than zero |

The promotion itself is `PayloadKernel.JailbreakByPid(pid, rootvnode)`, retried up to 30
times if it returns false. The outcome slot at `+0x0C` receives `0` on success and `-1`
on failure or on a header rejection.

## Wire format

Every request and every reply is a 2576-byte struct on the wire:

| Offset | Field | Size | Content |
|---|---|---|---|
| `+0x00` | Magic | `uint32` | `0xDEADBEEF` on the request; the daemon leaves it zero on the reply. |
| `+0x04` | Command | `int32` | `5` for a promotion request. |
| `+0x08` | Pid | `int32` | The caller's process identifier. |
| `+0x0C` | Return | `int32` | Zero on the request; `0` on success or `-1` on failure in the reply. |
| `+0x10` | Reserved | 1280 bytes | Zeroed on both sides. |
| `+0x510` | Reserved | 1280 bytes | Zeroed on both sides. |

The two reserved blocks are what the daemon's reader relies on for the read size, so
their presence matters even though nothing on the wire uses them today. They are room
for command extensions to grow into without breaking existing callers.

## Eleven-field promotion

`PayloadKernel.JailbreakByPid(pid, rootvnode)` walks the process list to locate `pid`
and then writes the following fields through the CRT-emitted per-field accessors:

| Field | Value |
|---|---|
| `cr_uid` | `0` |
| `cr_ruid` | `0` |
| `cr_svuid` | `0` |
| `cr_ngroups` | `0` |
| `cr_rgid` | `0` |
| `cr_sceAuthID` | `0x4801000000000013` |
| `cr_sceCaps[0]` | `0xFFFFFFFFFFFFFFFF` |
| `cr_sceCaps[1]` | `0xFFFFFFFFFFFFFFFF` |
| `cr_sceAttr0` | `0x80` |
| `fd_rdir` | `rootvnode` |
| `fd_jdir` | `rootvnode` |

The first nine writes lift the credential and capability set to the full-authorization
values. The last two point the target's file-descriptor root and jail directories at
the kernel's root vnode, so every path the target resolves afterwards starts from `/`.

## Building

Point the environment at the SDK once, then build the payload:

```
setx SHARPPROSPERO_ROOT "<sdk>"
pwsh $SHARPPROSPERO_ROOT/build/build-app.ps1 -ProjectPath samples/prospero-payload-unjail/SampleApp.csproj -Payload -Output Folder
```

The output is a single `SampleApp.elf` in the sample's `out/` folder. The build
pipeline is the same one every payload sample uses.

To include the diagnostic breadcrumbs (see below), rebuild with
`-DiagnosticBreadcrumbs`. Every build writes the same output name (`SampleApp.elf`);
rename the previous build first if both shapes need to sit alongside each other. The
two prebuilt ELFs the sample ships with follow that convention: `SampleApp.elf` is the
release build and `SampleApp.diag.elf` is a saved copy of the breadcrumb build.

## Calling the daemon from an application module

An application module that needs the extended view opens a loopback TCP connection to
`127.0.0.1:9069`, writes the 2576-byte request with its own pid, and reads the reply.

## Diagnostic breadcrumbs

Every step of the startup sequence and every accept-loop outcome writes a klog line.
Building with `-DiagnosticBreadcrumbs` keeps every log call in the ELF; a release build
strips the ones that are not on a failure path. The first missing line names the failed
step:

| Missing after | Failed step |
|---|---|
| (nothing at all) | The CRT never reached managed code. Check the loader's own log for a mapping failure. |
| `unjail: daemon start` | `PayloadEntryPoint.Args` returned null. The loader did not pass a `payload_args` block. |
| `unjail: args ok` | `getpid` returned zero or a negative value. The loader did not finish the pid setup before jumping to the payload. |
| `unjail: getpid ok` | Self-elevation faulted. Read the console log for the kernel-side line. |
| `unjail: authid set` | `GetRootVnode` returned zero: the running firmware is not covered by the CRT's root-vnode table. |
| `unjail: rootvnode cached` | The TCP setup failed. The next line (`socket failed`, `bind failed`, or `listen failed`) names the syscall. |

Once the accept loop is running, every request produces one of:

- `unjail: pid jailbroken` - the promotion succeeded and the client received `0`.
- `unjail: jailbreak failed` - the writes were rejected (the target exited before the sequence completed, or the CRT accessors returned an error).

## Extending

The wire format leaves the two reserved buffers empty and reserves the command slot
for growth. A daemon that needs additional operations can add commands without breaking
existing callers:

- **Command 6 - Restore.** Read the caller's ucred before applying the promotion, save
  it in the daemon, and add a restore command that writes it back. A module that
  promotes for one operation and returns afterwards uses this pair.
- **Command 7 - Promote another pid.** The caller names both its own pid (`+0x08`) and
  the target (in the reserved region). Useful when a controller module promotes a
  worker module.
- **Command 8 - Read a kernel word.** The daemon returns a `ulong` from a caller-supplied
  kernel address. Diagnostic; do not ship this on a public build.

Each extension follows the same shape: the caller writes the command in `+0x04`, the
daemon reads it in the accept loop, dispatches, and writes the outcome in `+0x0C`.
