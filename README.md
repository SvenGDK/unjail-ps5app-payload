# unjail-ps5app-payload

A persistent PS5 daemon payload. On launch it self-elevates, discovers the kernel root vnode, opens the kernel's nullfs mount gate on `prison0`, applies the shell-side `/data` and `/user` mount unlock, and opens a TCP listener on `127.0.0.1:9069`. For every accepted connection it reads a fixed 2576-byte request, dispatches one of twenty-one broker or install commands under the daemon's escalated credential, and returns the outcome in a fixed 2576-byte reply. The daemon stays running until the console reboots.

## When to send it

Send this payload once, before launching any homebrew application module that needs to reach paths outside its per-title sandbox, run a launch through the shell's install service, or write to a partition its own mount namespace does not bind.

The daemon runs inside the host process the loader chose. Only that host has the credential set and the pipe primitive that let it write another process's `ucred`, capability bitmasks, and `fd_rdir` / `fd_jdir` pointers, so the daemon is the only path an application module has to reach the extended view at run time.

## Supported firmwares

The daemon reads its kernel addresses through the CRT-emitted per-firmware accessors, which route every read through the firmware-versioned tables in `SharpProspero.Payload.Kernel.KernelOffsets`. The full 78-symbol table per firmware sits in `SharpProspero.Payload.Kernel.KernelOffsetTables.For(fw)`; the daemon consults the small subset it needs (`Allproc`, `KernelPmapStore`) through the boot-path gate `KernelOffsets.IsSupportedForUnjail(fw)`.

Coverage today (every firmware the upstream payload offset directory carries data for):

| Family | Firmwares |
|---|---|
| 1.xx | 1.00, 1.01, 1.02, 1.05, 1.10, 1.11, 1.12, 1.13, 1.14 |
| 2.xx | 2.00, 2.20, 2.25, 2.26, 2.30, 2.50, 2.70 |
| 3.xx | 3.00, 3.10, 3.20, 3.21 |
| 4.xx | 4.00, 4.02, 4.03, 4.50, 4.51 |
| 5.xx | 5.00, 5.02, 5.10, 5.50 |
| 6.xx | 6.00, 6.02, 6.50 |
| 7.xx | 7.00, 7.01, 7.20, 7.40, 7.60, 7.61 |
| 8.xx | 8.00, 8.20, 8.40, 8.60 |
| 9.xx | 9.00, 9.05, 9.20, 9.40, 9.60 |
| 10.xx | 10.00, 10.01, 10.20, 10.40, 10.60 |
| 11.xx | 11.00, 11.20, 11.40, 11.60 |
| 12.xx | 12.00, 12.02, 12.20, 12.40, 12.60, 12.70 |
| 13.xx | 13.00, 13.20, 13.40, 13.42, 13.60 |

Verified end-to-end on device: firmware 10.01. On every other firmware in the table the daemon runs the same code path; the offsets that vary between firmwares resolve through the CRT table without a rebuild.

The root-vnode read has two paths. A firmware whose `KernelOffsets.Rootvnode(fw)` is populated (every family except 13.xx today) reads the pointer directly from kernel data. A firmware without a Rootvnode entry falls through to the runtime discovery path: the daemon walks `allproc` to init (`pid=1`), reads its file-descriptor table's root directory, and caches the pointer. Either path returns the same vnode; the fall-through keeps the daemon starting on firmwares whose data-side pointer has not been pinned yet.

The structure field offsets the daemon uses through the CRT accessors (`cr_uid`, `cr_ruid`, `cr_svuid`, `cr_ngroups`, `cr_rgid`, `cr_sceAuthID`, `cr_sceCaps`, `cr_sceAttrs`, `fd_rdir`, `fd_jdir`) are firmware-invariant across every firmware in the coverage table, so the same daemon binary is correct across the whole range.

## Startup sequence

Every step emits a klog line, and every failure sends a user-visible kernel notification with the same string.

| Step | Klog line | On failure |
|---|---|---|
| 1 | `unjail: daemon start` | - |
| 2 | `unjail: args ok` | `unjail: no payload args` -> exit -1 |
| 3 | `unjail: firmware supported` | `unjail: unsupported firmware 0x<hex>` -> exit -1 |
| 4 | `unjail: getpid ok` | `unjail: getpid failed` -> exit -1 |
| 5 | `unjail: self raised` | - |
| 6 | `unjail: authid set` | - |
| 7 | `unjail: rootvnode cached` | `unjail: rootvnode read failed` -> exit -1 |
| 8 | `unjail: prison0 nullfs bit set ok` (or `already set`) | `unjail: prison0 nullfs bit write did not stick` / `unjail: prison0 not found` (continues) |
| 9 | `unjail: shellcore unlock ok` (or `partial`) | one of the specific unlock reasons below (continues) |
| 10 | `unjail: daemon ready, entering accept loop` (also as a system notification) | - |
| 11 | `unjail: tcp listener ready` | `unjail: socket failed` / `unjail: bind failed` / `unjail: listen failed` (exits the loop) |

Step 3 gates the whole daemon on the firmware-supported check. A firmware that returns zero from `KernelOffsets.IsSupportedForUnjail` fails cleanly at this step rather than reading the wrong quadword against a kdata offset that does not exist on the running kernel.

The self-elevation at steps 5 and 6 uses the same eleven-field promotion the daemon applies to callers, plus an authorization-id write. Without it the daemon's own kernel writes would fail the authorization check on the second call.

Step 9 rewrites the shell's `/data` / `/user` mount permission checks. Every check has one of these specific stop reasons on failure:

| Klog line | Reason |
|---|---|
| `unjail: shellcore unlock unsupported fw` | The pattern-scan table has no signatures for the running firmware. |
| `unjail: shellcore unlock no shellcore proc` | `allproc` walk did not find a `SceShellCore` process. |
| `unjail: shellcore unlock cr3 read failed` | Could not read the shell's page-table root through the pmap store. |
| `unjail: shellcore unlock module base not found` | The shell's own text section is not mapped where the pattern scan expects. |
| `unjail: shellcore unlock elf header read failed` | Could not read the shell's ELF header. |
| `unjail: shellcore unlock text segment not found` | The shell's ELF has no LOAD segment covering its text. |
| `unjail: shellcore unlock text segment too large` | Text segment exceeds the scratch buffer size. |
| `unjail: shellcore unlock scratch alloc failed` | The scratch buffer allocation refused. |
| `unjail: shellcore unlock text copyout failed` | `copyout` from the shell's address space refused. |
| `unjail: shellcore unlock signatures missed` | Signature bytes did not match at any site. |
| `unjail: shellcore unlock phys copyin rejected` | The write-back through the direct-map refused. |

A total miss does not fail the daemon start: broker-served access to the same paths still works through the daemon's TCP interface.

## Command set

Every request carries a 4-byte magic (`0xDEADBEEF`), a 4-byte command code, and up to 2568 bytes of payload. The reply mirrors the magic and command word, writes the primary result at `+0x08` (repeated at `+0x0C`), and packs data starting at `+0x20`. See the wire format section for the byte layout.

| Cmd | Name | Purpose |
|---|---|---|
| 5  | `CmdEscalate` | Promote the pid at `+0x08` to full authority. |
| 6  | `CmdStat` | `stat(2)` a path under the daemon's escalated view. |
| 7  | `CmdMkdir` | `mkdir(2)` with mode at `+0x18` (defaults to `0777`). |
| 8  | `CmdUnlink` | `unlink(2)`. |
| 9  | `CmdList` | `getdirentries(2)` paginated by an offset at `+0x08`; reply carries dirent bytes at `+0x20` and next-position at `+0x18`. |
| 10 | `CmdRead` | `pread`-shaped read: offset at `+0x08`, length at `+0x10`; reply carries bytes at `+0x20`. |
| 11 | `CmdWrite` | `pwrite`-shaped write: offset at `+0x08`, length at `+0x10`, bytes at `+0x220`; offset zero truncates. |
| 12 | `CmdRename` | Rename `+0x20` to `+0x220`. |
| 13 | `CmdStatfs` | `statfs(2)` a mount point; reply carries `f_fstypename` at `+0x20`. |
| 14 | `CmdUnmount` | `unmount(2)` with flags at `+0x18`. |
| 15 | `CmdMountNullfs` | `nmount(2)` a nullfs overlay of `+0x220` at `+0x20`. |
| 16 | `CmdRemountSystemEx` | `nmount(2)` `/system_ex` with `MNT_UPDATE` so the shell picks up new subdirectories. |
| 17 | `CmdFindPidByTitleId` | Walk `sysctl(KERN_PROC_PROC)` to find a running pid by title id. |
| 18 | `CmdArmLaunchAndWaitForExit` | Spawn a launch worker that calls `sceSystemServiceLaunchApp` and waits on `kqueue`/`EVFILT_PROC` for exit. |
| 19 | `CmdAppInstUtilInitialize` | `sceAppInstUtilInitialize` under the daemon's authority. |
| 20 | `CmdAppInstUtilAppUnInstall` | `sceAppInstUtilAppUnInstall` by title id at `+0x20`. |
| 21 | `CmdAppInstUtilAppInstallTitleDir` | Register a `(title id, dir)` pair with the install service; falls through to `sceAppInstUtilAppInstallAll(null)` on firmware groups where the entry point moved. |
| 22 | `CmdCopyDirRecursive` | Copy `+0x20` to `+0x220` recursively, escalated. |
| 23 | `CmdCopySceSysToAppmeta` | Copy a title's `sce_sys` layout to `/user/appmeta/<TID>`. |
| 24 | `CmdUpdateTrophy` | Trigger a trophy database refresh for a title. |
| 25 | `CmdCopyFile` | Copy a single file `+0x20` to `+0x220`. |

Every handler validates that its path fields are NUL-terminated within the declared length before use, and every one that talks to `libkernel` falls through to the raw syscall when the wrapper's own sandbox check refuses the path.

## Wire format

Every request and every reply is a 2576-byte struct on the wire. The magic and command words are always present; the meaning of the rest of the fields depends on the command.

| Offset | Field | Size | Content |
|---|---|---|---|
| `+0x00` | Magic | `uint32` | `0xDEADBEEF` on the request; the daemon mirrors it on the reply. |
| `+0x04` | Command | `int32` | Command code; the daemon mirrors it on the reply. |
| `+0x08` | Result / Aux | `int32`, `long`, or command-specific | On requests, either the pid (Cmd 5), a paginated resume offset (Cmd 9 / 10 / 11), or a `uint32` user id (Cmd 18). On replies, the primary outcome (0 on success, negative errno on failure); repeated at `+0x0C`. |
| `+0x10` | Length or size | `uint32`/`ulong` | Read/write length on the request; byte count of returned data or file size on the reply. |
| `+0x18` | Next / Mode / Flags | `long`/`uint32` | Next-position for `CmdList` replies; `mkdir` mode or `unmount` flags on the request. |
| `+0x20` | Path (broker) | 512 bytes | First path field (source path for rename / mount, target path elsewhere). |
| `+0x220` | Data / Second path | 2032 bytes | Write payload for `CmdWrite`, destination path for `CmdRename` / `CmdMountNullfs`, user-id for `CmdArmLaunchAndWaitForExit`. |

Replies zero the request-side fields they do not use and place the returned bytes at `+0x20` (2544 bytes of room, since the reply does not have to carry a duplicate copy of the path).

The daemon rejects a request whose magic word does not equal `0xDEADBEEF`, whose path field carries no NUL byte within the declared 512-byte length, or whose second-path field carries no NUL byte within the declared 2032-byte length. Every rejection sets the reply's primary outcome to `-22` (`EINVAL`).

## Eleven-field promotion

`PayloadKernel.JailbreakByPid(pid, rootvnode)` (invoked by `CmdEscalate`) walks the process list to locate `pid` and then writes the following fields through the CRT-emitted per-field accessors:

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

The first nine writes lift the credential and capability set to the full-authorization values. The last two point the target's file-descriptor root and jail directories at the kernel's root vnode, so every path the target resolves afterwards starts from `/`. `CmdEscalate` retries the sequence up to 30 times if the writes are rejected.

## Building

Point the environment at the SDK once, then build the payload:

```
setx SHARPPROSPERO_ROOT "<sdk>"
pwsh $SHARPPROSPERO_ROOT/build/build-app.ps1 -ProjectPath samples/prospero-payload-unjail/SampleApp.csproj -Payload -Output Folder
```

The output is a single `SampleApp.elf` in the sample's `out/` folder. The build pipeline is the same one every payload sample uses.

To include the diagnostic breadcrumbs (see below), rebuild with `-DiagnosticBreadcrumbs`. Every build writes the same output name (`SampleApp.elf`); rename the previous build first if both shapes need to sit alongside each other. The prebuilt ELFs the sample ships with follow that convention: `SampleApp.elf` is the release build and `SampleApp.diag.elf` is a saved copy of the breadcrumb build.

## Calling the daemon from an application module

An application module opens a loopback TCP connection to `127.0.0.1:9069`, writes a 2576-byte request with its own pid or paths in the command's fields, and reads the 2576-byte reply. Prospero Multi Tools bundles a client helper (`SharpProspero.Payload.Bypass.UnjailClient`); a bare-metal client follows the wire format table above.

## Diagnostic breadcrumbs

Every step of the startup sequence and every accept-loop outcome writes a klog line. Building with `-DiagnosticBreadcrumbs` keeps every log call in the ELF; a release build strips the ones that are not on a failure path. The first missing line names the failed step:

| Missing after | Failed step |
|---|---|
| (nothing at all) | The CRT never reached managed code. Check the loader's own log for a mapping failure. |
| `unjail: daemon start` | `PayloadEntryPoint.Args` returned null. The loader did not pass a `payload_args` block. |
| `unjail: args ok` | The firmware check refused (`IsSupportedForUnjail` returned false). |
| `unjail: firmware supported` | `getpid` returned zero or a negative value. The loader did not finish the pid setup. |
| `unjail: getpid ok` | Self-elevation faulted. Read the console log for the kernel-side line. |
| `unjail: authid set` | `GetRootVnode` returned zero: both the kdata read and the runtime discovery failed. |
| `unjail: rootvnode cached` | The `prison0` nullfs open or the shell-core unlock produced a specific error line (see the startup section). |
| `unjail: daemon ready, entering accept loop` | The TCP setup failed. The next line (`socket failed`, `bind failed`, or `listen failed`) names the syscall. |

Once the accept loop is running, every request produces one of:

- `unjail: pid jailbroken` - a promotion succeeded and the client received `0`.
- `unjail: jailbreak failed` - the writes were rejected (the target exited before the sequence completed, or the CRT accessors returned an error).
- `unjail: <op> rc=<value>` - every broker and install handler emits one line naming the operation and the raw return code (or `-errno` for a syscall failure).

## Extending

New commands add themselves to the `switch` in `TcpAcceptLoop`. Pick an unused command number, add a `HandleXxx` method that validates its path fields, applies the operation, and writes the result at `+0x08` (repeated at `+0x0C`). Every new symbol the handler needs from the kernel is available through `KernelOffsetTables.For(fw)` — the registry carries the full 78-symbol offset set (kdata pointers, text-side gadgets, secure-block loader landmarks, fPKG / PPR mount landmarks, the CR0 fast-transition chain, and struct `p_sysent`) for every firmware in the coverage table.
