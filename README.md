# RunasCS2

A minimal C# alternative to [RunasCs](https://github.com/antonioCoco/RunasCs) that fixes three behavioural issues found in the original.

## Background

RunasCs is a widely used Windows post-exploitation tool that runs commands as a different user via the `CreateProcessWithLogonW` Win32 API. During testing, three issues were identified in the original implementation that this project addresses.

## Fixes

### Fix 1 – Command string passed verbatim

**Original behaviour**: `ParseCommonProcessesInCommandline()` calls `commandline.Split(' ')` to replace short executable names (e.g. `cmd`, `powershell`) with their full paths, then reconstructs the string with `string.Join(" ", args)`. Any space inside a quoted argument causes incorrect tokenisation before the string reaches `CreateProcessWithLogonW`.

**RunasCS2**: the command string is passed directly as a `StringBuilder` to `CreateProcessWithLogonW` without any split/join. Short names such as `cmd` and `powershell` are resolved by the OS when `lpApplicationName` is `NULL`.

### Fix 2 – Unbounded output capture

**Original behaviour**: output is read into a single `byte[BUFFER_SIZE_PIPE]` (1 MB) array with one `ReadFile` call. Any output exceeding 1 MB is silently truncated.

**RunasCS2**: output is read in a streaming loop with an 8 KB buffer until the write end of the pipe is closed, capturing arbitrarily large output.

### Fix 3 – Accurate logon type via `LogonUser` + `CreateProcessAsUser`

**Original behaviour**: `CreateProcessWithLogonW` always performs an Interactive (type 2) logon internally, regardless of the `--logon-type` flag. The flag in RunasCs affects which code path is taken but not the actual Windows logon type used for types 2/3/8.

**RunasCS2**: when `--logon-type 2`, `3`, or `8` is given, the tool calls `LogonUser` with the exact `dwLogonType` value, then `CreateProcessAsUser` with the resulting token. This produces a logon session of precisely the requested type.

> **Requires**: `SeAssignPrimaryTokenPrivilege` on the calling process, or a SYSTEM-level caller. If unavailable, fall back to the default path (omit `--logon-type`).

### Fix 4 – `--bypass-uac` via `CreateProcessWithTokenW`

Uses `LogonUser` → `DuplicateTokenEx` (impersonation token) → `CreateProcessWithTokenW` to start the process with an elevated or differently-privileged token.

> **Requires**: `SeImpersonatePrivilege` on the calling process. Without it, the call fails with error 1314 (`ERROR_PRIVILEGE_NOT_HELD`).

## Build

**Linux (Mono)**:
```sh
mcs -out:RunasCS2.exe RunasCS2.cs
```

**Windows (.NET Framework)**:
```cmd
csc /out:RunasCS2.exe RunasCS2.cs
```

The produced executable is a standard .NET Framework binary and runs on Windows without Mono.

## Usage

```
RunasCS2.exe <username> <password> <command>
             [--domain <domain>]
             [--logon-type <2|3|8|9>]
             [--bypass-uac]
```

| Flag | Description |
|------|-------------|
| `--domain` | Domain name (default: `.` for local) |
| `--logon-type 2` | Interactive – `LogonUser` + `CreateProcessAsUser` |
| `--logon-type 3` | Network – `LogonUser` + `CreateProcessAsUser` |
| `--logon-type 8` | NetworkCleartext – `LogonUser` + `CreateProcessAsUser` |
| `--logon-type 9` | NewCredentials – `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)` |
| `--bypass-uac` | `LogonUser` + `DuplicateTokenEx` + `CreateProcessWithTokenW` |

Default (no flags): `CreateProcessWithLogonW(LOGON_WITH_PROFILE)`.

## Examples

```powershell
# Run a command as another local user (default path)
.\RunasCS2.exe alice P@ssw0rd "cmd /c whoami"

# Copy a file using PowerShell's Copy-Item (spaces in path work correctly)
.\RunasCS2.exe alice P@ssw0rd "powershell -c Copy-Item 'C:\path with spaces\file' 'C:\dest\file'"

# NetworkCleartext logon (type 8) — exact logon type, not a CreateProcessWithLogonW approximation
.\RunasCS2.exe alice P@ssw0rd "cmd /c whoami" --logon-type 8

# Attempt UAC bypass (requires SeImpersonatePrivilege)
.\RunasCS2.exe alice P@ssw0rd "cmd /c whoami /priv" --bypass-uac --logon-type 8

# Domain user
.\RunasCS2.exe alice P@ssw0rd "cmd /c whoami" --domain CORP
```

## Comparison with RunasCs

| Feature | RunasCs | RunasCS2 |
|---------|---------|----------|
| Quoted arguments with spaces | Broken by `Split(' ')` | Passed verbatim |
| Output size limit | 1 MB (hard-coded) | Unlimited (stream loop) |
| Exact logon type (2/3/8) | Always Interactive internally | `LogonUser` with exact type |
| `--bypass-uac` | Token manipulation via seclogon | `CreateProcessWithTokenW` |
| Privilege checks / suggestions | Yes (rich warnings) | Minimal |
| Remote impersonation | Yes | No |
| Process function selection | Yes (`--function`) | No |

RunasCS2 is intentionally minimal. For the full feature set (remote impersonation, process function selection, privilege diagnostics) use the original RunasCs.

## Notes on `dwLogonFlags` for `CreateProcessWithLogonW`

| Value | Constant | Effect on child process |
|-------|----------|------------------------|
| `0` | — | Full logon as specified user; profile not loaded |
| `1` | `LOGON_WITH_PROFILE` | Full logon as specified user; profile loaded |
| `2` | `LOGON_NETCREDENTIALS_ONLY` | Child inherits **caller's** primary token; specified credentials used only for outbound network auth |

RunasCs sets `logonFlags = 0` when the user profile directory does not exist (the common case for new or service accounts), so the child process receives the specified user's primary token and can access that user's local files even without `LOGON_WITH_PROFILE`.

## License

MIT
