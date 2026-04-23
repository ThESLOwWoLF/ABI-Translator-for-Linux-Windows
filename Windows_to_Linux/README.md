# Windows PE to Linux Reverse Loader

This folder contains the **reverse** Omni-Exec compatibility layer: loading and executing a Windows `.exe` (PE format) natively on a Linux host without an emulator.

## How It Works

1. **PE Parser**: `pe_loader.c` parses the Windows DOS stub, COFF headers, and Optional headers to find the executable `.text` section and the Entry Point RVA.
2. **Memory Map**: The loader uses Linux's `mmap()` to allocate a raw chunk of `PROT_EXEC` (executable) memory and copies the`.text` code there.
3. **ABI Translation (Trampoline)**: The Windows PE code expects function arguments in the MS x64 registers (`RCX, RDX, R8, R9`). However, Linux calling the function passes arguments in System V registers (`RDI, RSI, RDX, RCX`). 
   - *Elegant Solution:* Because we build this loader on Linux using GCC, we cast the memory pointer to a function pointer annotated with `__attribute__((ms_abi))`. GCC does the heavy lifting for us and automatically generates the trampoline that remaps the registers right before jumping!

## Prerequisites

- **Host Environment:** A native Linux system or Windows Subsystem for Linux (WSL).
- **Compiler:** `gcc` installed (`sudo apt install gcc`).

---

## Usage Guide

### 1. Generate a Test Windows PE file (`.exe`)
We've provided a C script that generates minimal Windows PE files containing raw math machine code (so you don't need a heavy Windows linker to test it).

Compile the generator *on Linux*:
```bash
gcc Test/create_test_pe.c -o create_test_pe
```
Generate an executable (e.g., the square function):
```bash
./create_test_pe square
```
*(This produces `square.exe`, a valid Windows binary!)*

### 2. Compile the PE Loader
Compile the loader natively on Linux:
```bash
gcc pe_loader.c -o pe_loader
```

### 3. Run the Windows `.exe` on Linux
Use the loader to execute the PE binary. Pass the file and an integer argument!
```bash
./pe_loader square.exe 7
```

**Expected Output:**
```text
==============================================
  Omni-Exec :: PE-on-Linux Loader
==============================================

-- Step 1: Parse PE Binary --
  Format       : Windows PE32+ (x86-64)
  Entry (RVA)  : 0x1000
  Sections     : 1
...
-- Step 2: Allocate Executable Memory (Linux mmap) --
  Loaded at    : 0x7fc7f4000000

-- Step 3 & 4: ABI Trampoline & Execute! --
  Executing Windows .exe code on Linux...
  Result: 49
```
*A Windows executable was successfully executed natively on Linux!*
