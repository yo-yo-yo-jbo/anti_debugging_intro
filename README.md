# Introduction to Anti-Debugging

Following my [shellcode analysis blogpost](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/) I felt the need to talk a bit more about shellcodes.  
One of the things an attacker might do is decide they don't wish to be analyzed. When we talk about analysis (reverse-engineering) there are generally two forms:
- Static analysis: examining the code without running it, usually involved a disassembler.
- Dynamic analysis: running the payload in a debugging environment, following the payload flow, setting up breakpoints and so on.

The quickest way (for me at least) to reverse-engineer a payload is combination of both. However, there are some hurdles along the way:
- For *static analysis*, the code author might decide to *obfuscate* the code - adding nonesense instructions, using a decryption key for the code, using [packing solutions](https://en.wikipedia.org/wiki/UPX) and even running the code in a [designated virtual machine](https://en.wikipedia.org/wiki/Denuvo).
- For *dynamic analysis*, the code author might decide to check the environment and behave differently based on it.

This blogpost aims to describe one particular aspect of an anti-dynamic-analysis: behave differently when being debugged, also known as *anti-debugging*.  
Note this is only an introduction-level blogpost - by no means is this a complete list of techniques.

It is important to note that *anti-debugging tricks are not bulletproof* - they can certainly slow down a researcher but will not be bullet-proof.  
In fact, some security products will actually flag binaries that use anti-debugging tricks since *they are more suspicious*, so keep that in mind!

## OS specific - Windows
If you come from a Windows background, you might be familiar with the [IsDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-isdebuggerpresent) WinAPI. Of course, the payload author could just invoke that API (if it's a shellcode then they'd need to resolve `kernel32.dll` before).  
Of course, sometimes it's useful to see how the API is implemented. Looking at `kernel32.dll` export of `IsDebuggerPresent` we see it's imported from `api-ms-win-core-debug-l1-1-0`, which is an [API set schema DLL](https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm), which eventually leads to `kernelbase.dll`.  
Well, let's examine the `IsDebuggerPresent` implementation:

```assembly
mov      rax, gs:60h
movzx    eax, byte ptr [rax+2]
ret
```

The IDA decompiler pains an even nicer picture:

```c
BOOL __stdcall IsDebuggerPresent()
{
  return NtCurrentPeb()->BeingDebugged;
}
```

That's quite interesting! If you recall, I mentioned the PEB [here](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/), but I'll save you a click or two: every process in Windows has some memory structure in its address space called the [PEB](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb), which saves useful information about the process in userspace. This is useful because the process doesn't have to talk to the kernel when it wants to get that information.  
In 32-bit systems, the PEB is pointed by `fs:30h` and in 64-bit: `gs:60h`. Moreover, the [PEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb) clearly states that the 3rd byte (i.e. offset 2 from the start) is the `BeingDebugged` flag, and indeed we see a dereference (`mozx   eax, byte ptr [rax+2]`).  
Therefore, if you're coding your own shellcode, an easy Windows-specific trick is checking that value straight from the PEB:

```assembly
_start:
	mov      rax, gs:60h
	movzx    eax, byte ptr [rax+2]
	test     eax, eax
	jnz      lbl_hang

; ...
; Rest of shellcode true logic comes here
; ...

lbl_hang:
	jmp lbl_hang
```

Of course, there are other Windows-specific debugging-aware APIs that can be useful (not a complete list by any means):
- [CheckRemoteDebuggerPresent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent) - similar to `IsDebuggerPresent` but implemented a bit differently.
- [OutputDebugString](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa) yields result (in `rax`) differently - if a debugger is present it'd be a valid address in the process address space, otherwise it gets 0 or 1 (depending on the OS version).
- [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) can be invoked on self-process and retrieve the `PEB` (with the `ProcessBasicInformation` information class) or even indicate debug ports (with the `ProcessDebugPort` information class).

Additionally, there are tricks that are more indirect - for example, checking the time that it takes to run instructions:
- [GetLocalTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlocaltime), [GetSystemTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime), [GetTickCount](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount) and others can be used twice - one to take a start time and one to take a finishing time. This will give us a `time delta` - if it's greater than a certain value then it's possible our payload is being debugged.
- The Intel `rdtsc` and `rdpmc` instructions can retrieve timestamps, and can be used just like those timing-based APIs.
- [QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter) can indicate timing differences as well.

Lastly, there are tool-specific heuristics:
- The [FindWindow](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa) API can indicate if a debugger window is open (e.g. looking for `x64dbg`, `IDA`, `Windbg` and so on).
- Similarly, looking for specific debugging processes (e.g. with [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) API) can indicate whether we are being debugged or not.

## OS-specific: Linux
Linux anti-debugging tricks share some commonalities with Windows.  
The approaches of checking the time and looking for process names dynamically are similar and I won't be covering them (easy to implement).  
Checking the `PEB` on Windows is kind of equivalent to checking the process status on Linux (`/proc/self/status`) and looking for the `TracerPid` which marks the debugger process ID:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_LEN (4096)
#define TRACER_MARKER ("TracerPid:")

int
is_being_debugged(void)
{
        int result = 0;
        FILE* fp = NULL;
        char buf[BUF_LEN] = { 0 };
        char* tracer_pid = NULL;

        // Open the status file
        fp = fopen("/proc/self/status", "r");
        if (NULL == fp)
        {
                goto cleanup;
        }

        // Read the file line-by-line
        while (fgets(buf, sizeof(buf), fp))
        {
                tracer_pid = strstr(buf, TRACER_MARKER);
                if (NULL != tracer_pid)
                {
                        result = (0 != atol(tracer_pid + strlen(TRACER_MARKER)));
                        break;
                }
        }

cleanup:

        // Cleanup
        if (NULL != fp)
        {
                fclose(fp);
                fp = NULL;
        }

        // Return result
        return result;
}

int main()
{
        printf("%d\n", is_being_debugged());
        return 0;
}
```
