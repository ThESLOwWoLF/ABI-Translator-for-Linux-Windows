# Omni-Exec

**A Bi-Directional Binary Compatibility Layer in C**

Omni-Exec is a proof-of-concept system that can run **Windows x86-64 PE binaries on Linux** and **Linux x86-64 ELF binaries on Windows** — without emulation or virtual machines. It works by parsing foreign binary formats, loading their code into executable memory, translating between the two OS calling conventions (ABIs), and jumping directly into the loaded code.

> **Course:** Compiler Design (CD) — Semester 6  
> **Purpose:** Demonstrates low-level concepts of binary loading, memory management, calling conventions, and code execution.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture Overview](#architecture-overview)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Building the Project](#building-the-project)
- [Usage](#usage)
- [Step-by-Step Walkthrough](#step-by-step-walkthrough)

---

## How It Works

When you compile a C program, the compiler produces a **binary executable** — a `.exe` (PE format) on Windows or an ELF binary on Linux. These files contain machine code (x86-64 instructions) that the CPU can execute directly. The machine instructions are **identical** on both platforms — what differs is:

1. **The binary container format** (PE vs ELF) — how headers, sections, and metadata are laid out in the file.
2. **The calling convention (ABI)** — which CPU registers hold function arguments.
3. **System calls** — how the program talks to the operating system.

Omni-Exec bridges all three gaps:

```
┌──────────────────────────────────────────────────────────────────┐
│                    OMNI-EXEC PIPELINE                            │
│                                                                  │
│  Foreign Binary ──► Parse ──► Load ──► Translate ABI ──► Jump!  │
│   (.exe / ELF)     (Step1)  (Step2)     (Step 3)       (Step 4) │
└──────────────────────────────────────────────────────────────────┘
```

---

## Architecture Overview

```
                    ┌─────────────────────┐
                    │   Foreign Binary     │
                    │  (.exe PE or ELF)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Step 1: Parser      │
                    │  omni_parser.c       │
                    │                      │
                    │  • Read magic bytes  │
                    │  • MZ → PE path      │
                    │  • 7F ELF → ELF path │
                    │  • Find entry point  │
                    │  • Find .text / LOAD │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Step 2: Memory      │
                    │  omni_memory.c/.h    │
                    │                      │
                    │  Linux:  mmap()      │
                    │    PROT_RWX          │
                    │  Windows:            │
                    │    VirtualAlloc()    │
                    │    PAGE_EXECUTE_RW   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Step 3: ABI Thunks  │
                    │  omni_thunks.c/.h    │
                    │  thunks_win.asm      │
                    │                      │
                    │  Windows x64 ABI:    │
                    │   RCX,RDX,R8,R9      │
                    │        ↕              │
                    │  System V ABI:       │
                    │   RDI,RSI,RDX,RCX    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Step 4: Jump!       │
                    │  omni_exec.c         │
                    │                      │
                    │  void* → fn pointer  │
                    │  fn(argument)        │
                    │  ← result in RAX     │
                    └─────────────────────┘
```

---

## Project Structure

```
Project/
│
├── omni_parser.c        Step 1 — Dual-format PE/ELF parser
│                         Detects format, extracts entry point
│
├── omni_memory.h        Step 2 — Cross-platform memory allocator (header)
├── omni_memory.c        Step 2 — Implementation (mmap / VirtualAlloc)
│
├── omni_thunks.h        Step 3 — ABI translation thunks (header)
├── omni_thunks.c        Step 3 — Implementation (register remapping)
├── thunks_win.asm       Step 3 — MASM trampoline for Windows host
│
├── omni_exec.c          Step 4 — Execution jump + integration tests
├── test_memory.c        Step 2 — Standalone memory allocator test
│
└── README.md            This file
```

---

## Prerequisites

### Windows
- **Microsoft Visual Studio 2022** (Community Edition is fine)
  - Requires the **"Desktop development with C++"** workload
  - This provides `cl.exe` (C compiler) and `ml64.exe` (MASM assembler)

### Linux
- **GCC** (any recent version with x86-64 support)
  ```bash
  sudo apt install build-essential    # Debian/Ubuntu
  sudo dnf install gcc                # Fedora
  ```

---

## Building the Project

### On Windows (Command Prompt)
Open a **Developer Command Prompt for VS 2022**, then run:

```batch
:: Navigate to the project directory
cd "C:\Users\sudha\Education\Study Docs\Amrita\SEM 6\CD\Project"

:: Step 1: Build the parser and the loader
cl omni_parser.c /Fe:omni_parser.exe
cl omni_loader.c omni_memory.c /Fe:omni_loader.exe

:: Step 2: Build the test ELF generator
cd Test
cl create_test_elf.c /Fe:create_test_elf.exe
cd ..
```

---

## Usage: How to Run the Project

The finalized version of Omni-Exec acts as a unified loader (`omni_loader.exe`). It takes a Linux ELF file and an integer argument, parses it, loads it, and executes the ELF code natively on Windows.

### 1. Generating a Test ELF
To demonstrate, first generate a valid Linux ELF containing x86-64 machine code:
```batch
.\Test\create_test_elf.exe square
```
*(This produces `square.elf` in your directory. You can also run `.\Test\create_test_elf.exe all` to generate 10 different math functions like cube, factorial, power2, etc.)*

### 2. Running the ELF on Windows
Pass the generated ELF file and a numerical argument to the loader:
```batch
.\omni_loader.exe square.elf 7
```
**Output Synopsis:**
```text
==============================================
  Omni-Exec :: ELF-on-Windows Loader
==============================================
-- Step 1: Parse ELF Binary --
  File           : square.elf
  Format         : Linux ELF64 (x86-64)
...
-- Step 4: Execute --
  Calling ELF code with argument: 7
  Result: 49
```
*A Linux ELF binary just executed natively on Windows without an emulator!*

---

## Running Your Own ELF Files & Current Limitations

You can define your own functions, compile them to an ELF on Linux (or WSL), and execute them through Omni-Exec on Windows. 

**What is supported right now:**
- ✅ **Pure computation:** Math, logic, arrays, and bitwise operations.
- ✅ **Control Flow:** Loops (`for`, `while`) and branching (`if`/`else`).
- ✅ **Returns:** Integer return values via registers.

**Example of supported custom C code:**
```c
// add.c - Pure math, no external includes!
int main() {
    int a = 2;
    int b = 3;
    return a + b;
}
```
Compile on Linux/WSL: `gcc -nostdlib -e main -static -o add.elf add.c`
Run on Windows: `.\omni_loader.exe add.elf 0` *(Result: 5)*

**What is NOT supported yet:**
- ❌ Standard Library functions (`#include <stdio.h>`)
- ❌ `printf`, `scanf`, strings, or file I/O
- ❌ Complex memory allocation (`malloc`, `free`)

**Why aren't strings or printf supported?**
While the x86-64 CPU instructions for basic math are identical on both Linux and Windows, OS interactions are completely different. A `printf` statement attempts to make a **Linux system call** (`sys_write`) to the Linux Kernel to write to standard output. Because Windows doesn't map these syscalls natively, our loader will fail if the ELF tries to talk to a missing kernel. 

To support I/O, strings, and standard library functions, we would need to build a **Full Syscall Translation Table** inside our ABI Thunks. This would intercept a Linux `sys_write` interrupt and translate it on-the-fly to a Windows `WriteConsoleA()` API call. The current version focuses successfully on pure execution, memory loading, and register remapping for computational functions!

---

## Step-by-Step Walkthrough

### Step 1: The Dual-Format Parser (`omni_parser.c`)

**Goal:** Given any x86-64 binary file, detect its format and find the entry point.

**How it works:**

1. **Read the first 4 bytes** (magic number) from the file:
   - `4D 5A` (`MZ`) → Windows PE format
   - `7F 45 4C 46` (`\x7FELF`) → Linux ELF format

2. **PE path:** Follow the header chain:
   ```
   DOS Header → e_lfanew offset → PE Signature → COFF Header → Optional Header → Section Table
   ```
   - `AddressOfEntryPoint` is in the Optional Header (it's an RVA — Relative Virtual Address)
   - The `.text` section in the Section Table contains the actual executable code

3. **ELF path:** Parse the ELF64 header directly:
   ```
   ELF Header → Program Header Table → scan for PT_LOAD + PF_X (executable segment)
   ```
   - `e_entry` in the ELF header is the virtual address of the entry point
   - The first executable `PT_LOAD` segment is where `.text` code lives

**Key structs used:** Only the fields needed to navigate to the entry point are defined — everything else is skipped or padded over.

---

### Step 2: Cross-Platform Memory Allocator (`omni_memory.h/.c`)

**Goal:** Allocate memory that is **readable, writable, AND executable** (RWX) — required to load foreign code and run it.

**How it works:**

| Host OS | API | Flags |
|---------|-----|-------|
| Windows | `VirtualAlloc()` | `MEM_COMMIT \| MEM_RESERVE`, `PAGE_EXECUTE_READWRITE` |
| Linux | `mmap()` | `PROT_READ \| PROT_WRITE \| PROT_EXEC`, `MAP_PRIVATE \| MAP_ANONYMOUS` |

Platform selection uses `#ifdef _WIN32` and `#ifdef __linux__` preprocessor directives.

**Three functions provided:**
- `allocate_executable_memory(size)` — allocate RWX memory
- `free_executable_memory(ptr, size)` — release it
- `load_section_into_memory(fp, offset, size)` — read a code section from a binary file directly into RWX memory

---

### Step 3: ABI Translation Thunks (`omni_thunks.h/.c`, `thunks_win.asm`)

**Goal:** Bridge the calling convention gap between Windows and Linux.

The x86-64 CPU instructions are identical on both OSes, but they disagree on **which registers carry function arguments**:

| Argument | Windows x64 (Microsoft ABI) | Linux (System V ABI) |
|----------|---------------------------|---------------------|
| 1st | `RCX` | `RDI` |
| 2nd | `RDX` | `RSI` |
| 3rd | `R8` | `RDX` |
| 4th | `R9` | `RCX` |
| Shadow space | 32 bytes on stack (required) | Not needed |

**Scenario A — Linux host running Windows PE code:**
- Uses GCC's `__attribute__((ms_abi))` to receive arguments in Windows registers (RCX, RDX, R8, R9)
- Inside the thunk, uses inline assembly to remap registers and invoke Linux syscalls
- Example: `WriteFile(handle, buf, count, &written, NULL)` → Linux `write(fd, buf, count)`

**Scenario B — Windows host running Linux ELF code:**
- MSVC doesn't support x64 inline assembly, so a MASM trampoline (`thunks_win.asm`) handles the register remapping
- The trampoline receives args in System V registers (RDI, RSI, RDX, RCX), remaps to Microsoft x64, then calls a C wrapper
- The C wrapper calls the equivalent Win32 API function
- Example: `write(1, buf, count)` → `WriteConsoleA(hStdOut, buf, count, &written, NULL)`

---

### Step 4: The Execution Jump (`omni_exec.c`)

**Goal:** Cast the raw memory address where code lives into a function pointer and call it.

**The core mechanism in 3 lines:**
```c
// 1. Define the function signature
typedef int (*entry_int_t)(int);

// 2. Cast void* (memory address) to a function pointer
entry_int_t fn = (entry_int_t)code_address;

// 3. Call it — the CPU jumps to that address and executes
int result = fn(42);
```

The test suite writes raw x86-64 machine code bytes into RWX memory and calls them:

| Test | Machine Code | What it computes |
|------|-------------|-----------------|
| Return 42 | `B8 2A 00 00 00 C3` | Always returns 42 |
| Double | `8D 04 09 C3` (Win) | `input * 2` |
| Multiply×7 | `6B C1 07 C3` (Win) | `input * 7` |
| n + n² | `89 C8 0F AF C1 01 C8 C3` (Win) | `n + n*n` |

> **Note:** The machine code bytes differ slightly between Windows and Linux because the first argument register is different (RCX vs RDI). The `#ifdef` preprocessor selects the correct variant at compile time.

---

## Key Concepts Demonstrated

| Concept | Where |
|---------|-------|
| Binary file format parsing (PE & ELF) | `omni_parser.c` |
| Magic numbers and file identification | `omni_parser.c` — `main()` |
| Struct-based header navigation | `omni_parser.c` — `DOS_Header`, `Elf64_Ehdr` |
| Platform-conditional compilation (`#ifdef`) | All files |
| OS-level memory management | `omni_memory.c` — `mmap` / `VirtualAlloc` |
| Executable memory (W⊕X bypass for loaders) | `omni_memory.c` |
| x86-64 calling conventions (ABIs) | `omni_thunks.c` |
| Inline assembly (GCC AT&T syntax) | `omni_thunks.c` — Linux thunks |
| MASM x86-64 assembly | `thunks_win.asm` |
| Function pointers and type casting | `omni_exec.c` — `execute_at()` |
| Raw machine code execution | `omni_exec.c` — test snippets |
| System call interception | `omni_thunks.c` — `thunk_write_*` |
