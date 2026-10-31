// RunasCS2.cs
// A focused alternative to RunasCs that fixes three behavioural issues:
//
//   Fix1: Command is passed verbatim to CreateProcessWithLogonW.
//         RunasCs does Split(' ') on the command string before reconstructing
//         it, which breaks arguments containing spaces inside quotes.
//
//   Fix2: Pipe output is read in a streaming loop.
//         RunasCs uses a fixed 1 MB buffer and a single ReadFile call, so
//         output larger than BUFFER_SIZE_PIPE is silently truncated.
//
//   Fix3: --logon-type uses LogonUser + CreateProcessAsUser so the Windows
//         logon type (2/3/8/9) is set exactly. CreateProcessWithLogonW
//         always performs an Interactive (type 2) logon internally regardless
//         of what the caller intends.
//
//   Fix4: --bypass-uac uses LogonUser + DuplicateTokenEx +
//         CreateProcessWithTokenW. Requires SeImpersonatePrivilege on the
//         calling process.
//
// Build (Linux / Mono):
//   mcs -out:RunasCS2.exe RunasCS2.cs
// Build (Windows .NET Framework):
//   csc /out:RunasCS2.exe RunasCS2.cs
//
// Usage:
//   RunasCS2.exe <username> <password> <command>
//                [--domain <domain>] [--logon-type <2|3|8|9>] [--bypass-uac]

using System;
using System.Runtime.InteropServices;
using System.Text;

class RunasCS2
{
    // ── P/Invoke ────────────────────────────────────────────────────────────

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithLogonW(
        string lpUsername, string lpDomain, string lpPassword,
        uint dwLogonFlags,
        string lpApplicationName, StringBuilder lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    // LogonUser で特定ログオン種別のトークンを取得 (type 2/3/8/9 対応)
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LogonUser(
        string lpszUsername, string lpszDomain, string lpszPassword,
        int dwLogonType, int dwLogonProvider,
        out IntPtr phToken);

    // LogonUser で得たトークンでプロセスを起動 (Assignable primary token 必要)
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName, StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    // bypass-uac 用: impersonation token でプロセスを起動 (SeImpersonatePrivilege 必要)
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(
        IntPtr hToken, uint dwLogonFlags,
        string lpApplicationName, StringBuilder lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,  // SecurityImpersonation=2
        int TokenType,           // TokenPrimary=1, TokenImpersonation=2
        out IntPtr phNewToken);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreatePipe(
        out IntPtr hReadPipe, out IntPtr hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadFile(
        IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // ── Structs ─────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars, dwFillAttribute;
        public int dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess, hThread;
        public int dwProcessId, dwThreadId;
    }

    // ── Constants ───────────────────────────────────────────────────────────

    const uint LOGON_WITH_PROFILE        = 0x00000001;
    const uint LOGON_NETCREDENTIALS_ONLY = 0x00000002;
    const uint CREATE_NO_WINDOW          = 0x08000000;
    const int  STARTF_USESTDHANDLES      = 0x00000100;
    const uint INFINITE                  = 0xFFFFFFFF;
    const uint HANDLE_FLAG_INHERIT       = 0x00000001;

    // LogonUser dwLogonType
    const int LOGON32_LOGON_INTERACTIVE      = 2;
    const int LOGON32_LOGON_NETWORK          = 3;
    const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    const int LOGON32_LOGON_NEW_CREDENTIALS  = 9;
    const int LOGON32_PROVIDER_DEFAULT       = 0;

    // DuplicateTokenEx
    const uint TOKEN_ALL_ACCESS      = 0x000F01FF;
    const int  SecurityImpersonation = 2;
    const int  TokenPrimary          = 1;
    const int  TokenImpersonation    = 2;

    // ── Entry point ─────────────────────────────────────────────────────────

    static int Main(string[] args)
    {
        if (args.Length < 3)
        {
            Console.Error.WriteLine("Usage: RunasCS2 <username> <password> <command>");
            Console.Error.WriteLine("       [--domain <domain>] [--logon-type <2|3|8|9>] [--bypass-uac]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("  --logon-type 2  : Interactive  (LogonUser + CreateProcessAsUser)");
            Console.Error.WriteLine("  --logon-type 3  : Network      (LogonUser + CreateProcessAsUser)");
            Console.Error.WriteLine("  --logon-type 8  : NetworkCleartext (LogonUser + CreateProcessAsUser)");
            Console.Error.WriteLine("  --logon-type 9  : NewCredentials (CreateProcessWithLogonW /netonly)");
            Console.Error.WriteLine("  --bypass-uac    : CreateProcessWithTokenW (requires SeImpersonatePrivilege)");
            return 1;
        }

        string username   = args[0];
        string password   = args[1];
        string command    = args[2];   // verbatim — Fix1
        string domain     = ".";
        int    logonType  = 0;         // 0 = use CreateProcessWithLogonW (デフォルト)
        bool   bypassUac  = false;

        for (int i = 3; i < args.Length; i++)
        {
            if (args[i] == "--domain" && i + 1 < args.Length)
                domain = args[++i];
            else if (args[i] == "--logon-type" && i + 1 < args.Length)
                logonType = int.Parse(args[++i]);
            else if (args[i] == "--bypass-uac")
                bypassUac = true;
        }

        if (username.Contains("\\"))
        {
            string[] parts = username.Split(new char[] { '\\' }, 2);
            domain   = parts[0];
            username = parts[1];
        }

        // ── パイプ作成 ───────────────────────────────────────────────────────

        var sa = new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),
            bInheritHandle = true,
            lpSecurityDescriptor = IntPtr.Zero
        };

        IntPtr hRead, hWrite;
        if (!CreatePipe(out hRead, out hWrite, ref sa, 0))
            return Die("CreatePipe");

        SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

        var si = new STARTUPINFO
        {
            cb         = Marshal.SizeOf(typeof(STARTUPINFO)),
            dwFlags    = STARTF_USESTDHANDLES,
            hStdInput  = IntPtr.Zero,
            hStdOutput = hWrite,
            hStdError  = hWrite
        };

        var cmdSb = new StringBuilder(command);  // Fix1: verbatim

        PROCESS_INFORMATION pi;
        bool ok;

        // ── プロセス起動: 方法を選択 ─────────────────────────────────────────

        if (bypassUac)
        {
            // Fix4: --bypass-uac
            // LogonUser でトークンを取得し、CreateProcessWithTokenW で起動。
            // SeImpersonatePrivilege がないと ERROR_PRIVILEGE_NOT_HELD (1314) になる。
            ok = LaunchWithTokenW(username, domain, password, logonType,
                                  cmdSb, ref si, out pi);
        }
        else if (logonType != 0 && logonType != 9)
        {
            // Fix3: --logon-type 2/3/8 → LogonUser + CreateProcessAsUser
            // CreateProcessWithLogonW はログオン種別を直接指定できないが、
            // LogonUser は dwLogonType を正確に指定できる。
            ok = LaunchAsUser(username, domain, password, logonType,
                              cmdSb, ref si, out pi);
        }
        else
        {
            // デフォルト / --logon-type 9 (NewCredentials)
            uint flags = (logonType == 9)
                ? LOGON_NETCREDENTIALS_ONLY
                : LOGON_WITH_PROFILE;

            ok = CreateProcessWithLogonW(
                username, domain, password,
                flags, null, cmdSb,
                CREATE_NO_WINDOW, IntPtr.Zero, null,
                ref si, out pi);

            if (!ok)
            {
                CloseHandle(hWrite);
                CloseHandle(hRead);
                return Die("CreateProcessWithLogonW");
            }
        }

        CloseHandle(hWrite);

        if (!ok)
        {
            CloseHandle(hRead);
            return 1;
        }

        // ── Fix2: ストリームループで出力を無制限に読む ───────────────────────

        var outStream = Console.OpenStandardOutput();
        byte[] buf = new byte[8192];
        uint bytesRead;

        while (ReadFile(hRead, buf, (uint)buf.Length, out bytesRead, IntPtr.Zero) && bytesRead > 0)
            outStream.Write(buf, 0, (int)bytesRead);

        WaitForSingleObject(pi.hProcess, INFINITE);

        uint exitCode = 0;
        GetExitCodeProcess(pi.hProcess, out exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);

        return (int)exitCode;
    }

    // ── Fix3: LogonUser + CreateProcessAsUser ───────────────────────────────

    static bool LaunchAsUser(string username, string domain, string password,
                             int logonType, StringBuilder cmdSb,
                             ref STARTUPINFO si, out PROCESS_INFORMATION pi)
    {
        pi = new PROCESS_INFORMATION();
        IntPtr hToken;

        if (!LogonUser(username, domain, password, logonType, LOGON32_PROVIDER_DEFAULT, out hToken))
        {
            Die(string.Format("LogonUser (logon-type={0})", logonType));
            return false;
        }

        bool ok = CreateProcessAsUser(
            hToken, null, cmdSb,
            IntPtr.Zero, IntPtr.Zero,
            true,               // bInheritHandles
            CREATE_NO_WINDOW,
            IntPtr.Zero, null,
            ref si, out pi);

        CloseHandle(hToken);

        if (!ok) Die("CreateProcessAsUser");
        return ok;
    }

    // ── Fix4: LogonUser + DuplicateTokenEx + CreateProcessWithTokenW ─────────

    static bool LaunchWithTokenW(string username, string domain, string password,
                                 int logonType, StringBuilder cmdSb,
                                 ref STARTUPINFO si, out PROCESS_INFORMATION pi)
    {
        pi = new PROCESS_INFORMATION();

        int lt = (logonType != 0) ? logonType : LOGON32_LOGON_INTERACTIVE;
        IntPtr hToken;

        if (!LogonUser(username, domain, password, lt, LOGON32_PROVIDER_DEFAULT, out hToken))
        {
            Die(string.Format("LogonUser (bypass-uac, logon-type={0})", lt));
            return false;
        }

        // Impersonation token (SecurityImpersonation) が必要
        IntPtr hDup;
        bool dup = DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, IntPtr.Zero,
                                    SecurityImpersonation, TokenImpersonation, out hDup);
        CloseHandle(hToken);

        if (!dup)
        {
            Die("DuplicateTokenEx");
            return false;
        }

        bool ok = CreateProcessWithTokenW(
            hDup, LOGON_WITH_PROFILE,
            null, cmdSb,
            CREATE_NO_WINDOW,
            IntPtr.Zero, null,
            ref si, out pi);

        CloseHandle(hDup);

        if (!ok) Die("CreateProcessWithTokenW (SeImpersonatePrivilege が必要)");
        return ok;
    }

    // ────────────────────────────────────────────────────────────────────────

    static int Die(string msg)
    {
        Console.Error.WriteLine("[-] {0} failed with error: {1}", msg, Marshal.GetLastWin32Error());
        return 1;
    }
}
