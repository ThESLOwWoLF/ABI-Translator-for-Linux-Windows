# ABI-Translator-for-Linux-Windows

**Name:** Omni-Exec
**Purpose:** A Bi-Directional Binary Compatibility Layer (x86-64)
**Course Domain:** Compiler Design (CD)
**Core Concept:** x86-64 machine code is universal. We can execute a Linux `.elf` natively on Windows, and a Windows `.exe` natively on Linux without a virtual machine or emulator, simply by performing ABI translation and memory hacking.

## Current State: COMPLETELY FUNCTIONAL
The project successfully works in BOTH directions.
It is divided into two separate directories:
1. `Linux_to_Windows/`: Parses Linux ELF64 binaries and executes them natively on Windows via MSVC C/MASM tooling.
2. `Windows_to_Linux/`: Parses Windows PE32+ `.exe` binaries and executes them natively on Linux via GCC tooling.

## The 4-Stage Execution Pipeline
In both directions, the loaders follow 4 precise steps:
1. **The Parser:** Reads the magic bytes (`MZ` for Windows, `\x7FELF` for Linux). Steps through the raw binary headers (DOS->COFF->Optional, or ELF64->PHDR) to locate exactly where the executable `.text` segment payload lives, and extracts the Entry Point (VA/RVA).
2. **The Memory Allocator:** Uses native OS APIs (Windows: `VirtualAlloc`, Linux: `mmap`) to allocate a raw chunk of `PROT_EXEC` (Readable/Writable/Executable) memory and copies the raw code segment from the binary file into RAM.
3. **The ABI Trampoline:** The most important Compiler Design aspect. Windows (Microsoft x64 ABI) passes args via `RCX, RDX, R8, R9`. Linux (System V ABI) passes args via `RDI, RSI, RDX, RCX`. The loaders create a small trampoline that intercepts the function call and remaps these registers so the foreign executable receives data exactly how it expects.
4. **Execution Jump:** We cast the memory address to a C function pointer and execute it. The x86 CPU takes over natively. The return value is intercepted from the `EAX/RAX` register and printed by the host system.
