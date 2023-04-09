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

And we can run with and without `gdb` for comparison:
```shell
┌──(jbo@linjbo)-[/tmp/debugging]
└─$ ./is_debugged
0

┌──(jbo@linjbo)-[/tmp/debugging]
└─$ gdb -ex "r" -ex "q" ./is_debugged
GNU gdb (Debian 12.1-4+b1) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./is_debugged...
(No debugging symbols found in ./is_debugged)
Starting program: /tmp/is_debugged
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
1
[Inferior 1 (process 161) exited normally]
```

Another Linux-specific concept (that could be achieved under Windows too) is *self-debugging*. Abusing the fact that a process can only be debugged once, self-debugging simply stops another debugger from being attached. Simply call `ptrace(PTRACE_TRACEME, 0, 1, 0)`.

## Intel-specific techniques
Those techniques are not OS-specific (but are architecture specific). I will mention two here, and explain by example.

### Looking for breakpoints
Setting a `debugger breakpoint` on Intel architectures actually patches the code - it adds an `int 3` instruction.  
Interrupt 3 is a debug breakpoint, and takes one opcode with no operands, encoded as `0xCC`. Therefore, looking for `0xCC` makes sense. Here is a quick example:

```assembly
0x0000000000000000:  E8 00 00 00 00          call        5
0x0000000000000005:  5F                      pop         rdi
0x0000000000000006:  48 C7 C1 00 02 00 00    mov         rcx, 0x200
0x000000000000000d:  FC                      cld         
0x000000000000000e:  B0 CB                   mov         al, 0xcb
0x0000000000000010:  FE C0                   inc         al
0x0000000000000012:  F2 AE                   repne scasb al, byte ptr [rdi]
0x0000000000000014:  67 E3 02                jecxz       0x19
0x0000000000000017:  EB FE                   jmp         0x17
			...
```

What's going on here? Let's analyze line by line:
- The first two lines are an easy `call-pop` shellcode trick - basically `rdi` gets the address of the shellcode (plus 5 instructions in).
- Next, we set the stage for a string operation: `rcx` has the shellcode length (I just chose `0x200` at random), the direction flag is cleared and `al` is being set. Note we set `al` to be `0xCB` and then increase it by one to get `0xCC`. More on that later.
- We call `repne scasb`, which will look for `al` (`0xCC` byte) starting `rdi` (where the shellcode starts) for `rcx` (`0x200`) bytes.
- We use the `jecxz` instruction to jump if `ecx` is zero, which is should be unless we found a `0xCC` byte.
- If we do not jump - we hang in an endless loop at offset `0x17`.

Why did we set `al` to be `0xCB` and increase it instead of setting it directly to `0xCC`? Well, Note that `mov al, 0xcc` is encoded as `B0 CC`, so our "int 3 detection" would definitely detect a `0xCC` byte there, so that's a necessity.

Of course, similar things can be done in highlevel code - not just assembly.

### Looking for hardware debug breakpoints
The debug breakpoint we saw so far is implemented in software (`int 3` is a *software interrupt*).  
However, Intel supports *hardware debugging*, which is usually translated to setting a breakpoint on read or write:
- In `gdb` you'll find that in the `watch` and `rwatch` commands.
- In `Visual Studio` you'll find an option to add a `data breakpoint`.

Hardware breakpoints are implemented in specialized [debug registers](https://en.wikipedia.org/wiki/X86_debug_register).
- It's not necessary to dive into the bits and bytes of them - just to know that they reflect the state of hardware breakpoints.
- One cannot access those debug registers from userland - accessing them is only permitted from `ring 0` (kernel).

