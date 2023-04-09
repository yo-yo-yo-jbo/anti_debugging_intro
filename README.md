# Introduction to Anti-Debugging

Following my [shellcode analysis blogpost](https://github.com/yo-yo-yo-jbo/msf_shellcode_analysis/) I felt the need to talk a bit more about shellcodes.  
One of the things an attacker might do is decide they don't wish to be analyzed. When we talk about analysis (reverse-engineering) there are generally two forms:
- Static analysis: examining the code without running it.
- Dynamic analysis: running the payload in a debugging environment, following the payload flow, setting up breakpoints and so on.

The quickest way (for me at least) to reverse-engineer a payload is combination of both. However, there are some hurdles along the way:
- For *static analysis*, the code author might decide to *obfuscate* the code - adding nonesense instructions, using a decryption key for the code and even running the code in a designated virtual machine.
- For *dynamic analysis*, the code author might decide to check the environment and behave differently based on it.

This blogpost aims to describe one particular aspect of an anti-dynamic-analysis: behave differently when being debugged, also known as *anti-debugging*.
