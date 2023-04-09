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

## OS specific
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


