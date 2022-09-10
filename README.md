# Understanding 64 bits Windows Shellcoding

This repository is written in conjunction with the [blog post](https://owl4444.github.io/2022/09/07/Understanding_64_bits_Windows_10_Shellcode/). During this time, I want to understand in full details on a possible implementation. This post aims at understanding the basic concept of writing shellcode without focusing on any encodings, non-null, obfuscation or any special methods in making undetectable shellcodes.

## The Goal

With the concepts covered, I believe that we can always tweak it to run other payloads. As of now, we have :

```c
// to spawn a calculator
WinExec("calc.exe",1);
```

---
