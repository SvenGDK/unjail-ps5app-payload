// Daemon payload: self-elevates, then listens on a TCP socket for credential escalation
// requests from application modules. Each request carries a process identifier in a fixed
// binary layout; the daemon applies the eleven-field credential and filesystem write
// sequence through CRT-emitted per-field accessors, replies with the outcome, and continues.
//
// Kernel address offsets come from the CRT-embedded per-firmware table. Major versions 1
// through 10 ship verified offsets; on 11.x and later the root-vnode offset resolves to
// zero, so the startup vnode read fails and the daemon exits early. All kernel access
// routes through the CRT-emitted accessors, which share a single pipe-primitive call
// chain initialised once during CRT startup from the loader's payload_args block.

using System;
using System.Runtime.InteropServices;
using SharpProspero.Payload;
using SharpProspero.Payload.Kernel;
using SharpProspero.Payload.Process;
using SharpProspero.Payload.Services;

namespace SampleApp;

internal static unsafe class Program
{
    // ---- FreeBSD socket constants ----

    private const int AF_INET      = 2;
    private const int SOCK_STREAM  = 1;
    private const int SOL_SOCKET   = 0xFFFF;
    private const int SO_REUSEADDR = 0x0004;

    // ---- Protocol constants ----

    private const int DaemonPort     = 9069;
    private const int CommandSize    = 0xA10;
    private const uint ExpectedMagic = 0xDEADBEEF;
    private const int EscalationCmd  = 5;
    private const int MaxRetries     = 30;

    // ---- Socket and IO wrappers ----

    private static long SysRead(int fd, byte* buf, long count) =>
        PayloadCrt.Syscall(PayloadCrt.SYS_read, fd, (long)(nint)buf, count);

    private static long SysWrite(int fd, byte* buf, long count) =>
        PayloadCrt.Syscall(PayloadCrt.SYS_write, fd, (long)(nint)buf, count);

    private static int SysClose(int fd) =>
        (int)PayloadCrt.Syscall(PayloadCrt.SYS_close, fd);

    private static void SleepOneSecond()
    {
        long* ts = stackalloc long[4];
        ts[0] = 1;  // tv_sec
        ts[1] = 0;  // tv_nsec
        PayloadCrt.Syscall(PayloadCrt.SYS_nanosleep, (long)(nint)ts, (long)(nint)(ts + 2));
    }

    // ---- Entry point ----

    [UnmanagedCallersOnly(EntryPoint = "__managed__Main")]
    public static int Main(void* args)
    {
        PayloadCrt.Klog("unjail: daemon start\n\0"u8);

        PayloadArgs* pargs = PayloadEntryPoint.Args;
        if (pargs == null)
        {
            PayloadCrt.Klog("unjail: no payload args\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: no payload args"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: args ok\n\0"u8);

        int ownPid = PayloadProcessControl.getpid();
        if (ownPid <= 0)
        {
            PayloadCrt.Klog("unjail: getpid failed\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: getpid failed"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: getpid ok\n\0"u8);

        PayloadKernel.RaisePrivileges(ownPid);
        PayloadCrt.Klog("unjail: self raised\n\0"u8);

        PayloadKernel.SetUcredAuthId(ownPid, 0x4800000000010003);
        PayloadCrt.Klog("unjail: authid set\n\0"u8);

        ulong rootvnode = PayloadKernel.GetRootVnode();
        if (rootvnode == 0)
        {
            PayloadCrt.Klog("unjail: rootvnode read failed\n\0"u8);
            PayloadNotification.SendKernelNotification("unjail: rootvnode read failed"u8);
            return -1;
        }
        PayloadCrt.Klog("unjail: rootvnode cached\n\0"u8);

        PayloadNotification.SendKernelNotification("unjail: daemon ready"u8);
        PayloadCrt.Klog("unjail: daemon ready, entering accept loop\n\0"u8);

        TcpAcceptLoop(rootvnode);
        return 0;
    }

    // ---- TCP accept loop ----

    private static void TcpAcceptLoop(ulong rootvnode)
    {
        int s = (int)PayloadCrt.Syscall(PayloadCrt.SYS_socket, AF_INET, SOCK_STREAM, 0);
        if (s < 0)
        {
            PayloadCrt.Klog("unjail: socket failed\n\0"u8);
            return;
        }

        int one = 1;
        PayloadCrt.Syscall(PayloadCrt.SYS_setsockopt, s, SOL_SOCKET, SO_REUSEADDR,
                     (long)(nint)(&one), 4);

        // FreeBSD sockaddr_in: sin_len(1), sin_family(1), sin_port(2 BE),
        // sin_addr(4), sin_zero(8). Total 16 bytes.
        byte* addr = stackalloc byte[16];
        new Span<byte>(addr, 16).Clear();
        addr[0] = 16;                          // sin_len
        addr[1] = (byte)AF_INET;               // sin_family
        addr[2] = (byte)(DaemonPort >> 8);      // sin_port high (big-endian)
        addr[3] = (byte)(DaemonPort & 0xFF);    // sin_port low
        addr[4] = 127; addr[5] = 0; addr[6] = 0; addr[7] = 1;  // sin_addr = 127.0.0.1

        if (PayloadCrt.Syscall(PayloadCrt.SYS_bind, s, (long)(nint)addr, 16) < 0)
        {
            PayloadCrt.Klog("unjail: bind failed\n\0"u8);
            SysClose(s);
            return;
        }

        if (PayloadCrt.Syscall(PayloadCrt.SYS_listen, s, 2) < 0)
        {
            PayloadCrt.Klog("unjail: listen failed\n\0"u8);
            SysClose(s);
            return;
        }

        PayloadCrt.Klog("unjail: tcp listener ready\n\0"u8);

        byte* cmdBuf   = stackalloc byte[CommandSize];
        byte* replyBuf = stackalloc byte[CommandSize];

        while (true)
        {
            int client = (int)PayloadCrt.Syscall(PayloadCrt.SYS_accept, s, 0, 0);
            if (client < 0)
            {
                SleepOneSecond();
                continue;
            }

            int total = 0;
            while (total < CommandSize)
            {
                long n = SysRead(client, cmdBuf + total, CommandSize - total);
                if (n <= 0) break;
                total += (int)n;
            }

            new Span<byte>(replyBuf, CommandSize).Clear();

            if (total >= 16)
            {
                uint magic = *(uint*)(cmdBuf + 0);
                int  cmd   = *(int*)(cmdBuf + 4);
                int  pid   = *(int*)(cmdBuf + 8);

                if (magic == ExpectedMagic && cmd == EscalationCmd && pid > 0)
                {
                    bool ok = false;
                    for (int r = 0; r < MaxRetries && !ok; r++)
                        ok = PayloadKernel.JailbreakByPid(pid, rootvnode);

                    *(int*)(replyBuf + 0x0C) = ok ? 0 : -1;
                    PayloadCrt.Klog(ok ? "unjail: pid jailbroken\n\0"u8 : "unjail: jailbreak failed\n\0"u8);
                }
                else
                {
                    *(int*)(replyBuf + 0x0C) = -1;
                }
            }
            else
            {
                *(int*)(replyBuf + 0x0C) = -1;
            }

            SysWrite(client, replyBuf, CommandSize);
            SysClose(client);
        }
    }
}
