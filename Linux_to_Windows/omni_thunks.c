/*
 * Omni-Exec — Step 3: ABI Translation Thunks (Implementation)
 * ─────────────────────────────────────────────────────────────
 *
 * This file provides thunk functions for BOTH directions:
 *
 *   SCENARIO A  (Host: Linux,   Guest: Windows PE)
 *     - PE code calls "Windows API" stubs → thunks remap registers
 *       → perform Linux syscalls.
 *     - Uses GCC's __attribute__((ms_abi)) so the function receives
 *       arguments in RCX, RDX, R8, R9 (Windows convention), even
 *       though we're compiling on Linux.
 *
 *   SCENARIO B  (Host: Windows, Guest: Linux ELF)
 *     - ELF code calls "Linux syscall" stubs → thunks remap registers
 *       → call Win32 API functions.
 *     - MSVC does not support x64 inline assembly, so we use C-level
 *       wrappers and provide a companion .asm file for the actual
 *       register-level trampoline.
 *
 * Build:
 *   Linux:    gcc -c omni_thunks.c -o omni_thunks.o
 *   Windows:  cl /c omni_thunks.c
 */

#include "omni_thunks.h"
#include <stdio.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════
 *  SCENARIO A:  Host = Linux  →  Guest = Windows PE
 *  ─────────────────────────────────────────────────
 *  GCC's __attribute__((ms_abi)) tells the compiler:
 *    "This function uses the Microsoft x64 calling convention."
 *  So when the PE binary calls these functions, arguments arrive
 *  in RCX, RDX, R8, R9 — exactly what Windows code expects.
 *  Inside the thunk, we translate to Linux syscalls.
 * ═══════════════════════════════════════════════════════════════════ */

#ifdef __linux__

#include <unistd.h>
#include <sys/syscall.h>

/*
 * thunk_write_linux  —  Emulates Windows WriteFile() on Linux
 * ────────────────────────────────────────────────────────────
 * Windows PE code calls:
 *   WriteFile(handle, buffer, count, &written, overlapped)
 *   → arrives as:  RCX=handle, RDX=buffer, R8=count, R9=&written
 *
 * We translate to Linux:
 *   write(fd, buf, count)
 *   → syscall #1:  RDI=fd, RSI=buf, RDX=count
 *
 * The __attribute__((ms_abi)) makes GCC receive args in MS registers.
 */
__attribute__((ms_abi))
static int64_t thunk_write_linux(int64_t handle,    /* RCX → fd      */
                                 int64_t buffer,     /* RDX → buf ptr */
                                 int64_t count,      /* R8  → size    */
                                 int64_t p_written)  /* R9  → &written*/
{
    int64_t result;

    /*
     * Inline assembly: perform the Linux write syscall.
     *
     *   syscall #1 = write(fd, buf, count)
     *   Arguments:  RAX = syscall number
     *               RDI = fd
     *               RSI = buffer pointer
     *               RDX = byte count
     *
     * The registers are remapped from Windows ABI → Linux syscall ABI:
     *   RCX (handle)  →  RDI (fd)
     *   RDX (buffer)  →  RSI (buf)
     *   R8  (count)   →  RDX (count)
     */
    __asm__ __volatile__ (
        "mov $1, %%rax\n\t"       /* RAX = 1 (sys_write)              */
        "mov %1,  %%rdi\n\t"      /* RDI = handle (fd)                */
        "mov %2,  %%rsi\n\t"      /* RSI = buffer pointer             */
        "mov %3,  %%rdx\n\t"      /* RDX = byte count                 */
        "syscall\n\t"             /* Invoke kernel                    */
        "mov %%rax, %0\n\t"       /* result = return value            */
        : "=r" (result)                                /* output      */
        : "r" (handle), "r" (buffer), "r" (count)      /* inputs      */
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11",    /* clobbers    */
          "memory"
    );

    /* Store bytes written into the caller's pointer (like WriteFile) */
    if (p_written) {
        *((int64_t*)p_written) = result;
    }

    printf("[thunk] write: fd=%lld, buf=%p, count=%lld → wrote %lld bytes\n",
           (long long)handle, (void*)buffer,
           (long long)count, (long long)result);

    return result;
}

/*
 * thunk_exit_linux  —  Emulates ExitProcess() on Linux
 * ────────────────────────────────────────────────────
 * Windows PE calls:  ExitProcess(exit_code)  →  RCX = exit_code
 * Linux syscall:     exit_group(code)        →  RAX=231, RDI=code
 */
__attribute__((ms_abi))
static int64_t thunk_exit_linux(int64_t exit_code,   /* RCX → code   */
                                int64_t unused1,
                                int64_t unused2,
                                int64_t unused3)
{
    (void)unused1; (void)unused2; (void)unused3;

    printf("[thunk] ExitProcess(%lld) → sys_exit_group\n",
           (long long)exit_code);

    __asm__ __volatile__ (
        "mov $231, %%rax\n\t"     /* RAX = 231 (sys_exit_group)       */
        "mov %0,   %%rdi\n\t"     /* RDI = exit code                  */
        "syscall\n\t"
        :
        : "r" (exit_code)
        : "rax", "rdi"
    );

    return 0;  /* Never reached */
}

/* ── Thunk table for Linux host ──────────────────────────────────── */
static ThunkEntry linux_thunks[] = {
    { "WriteFile",    thunk_write_linux },
    { "ExitProcess",  thunk_exit_linux  },
};
#define THUNK_COUNT (sizeof(linux_thunks) / sizeof(linux_thunks[0]))


/* ═══════════════════════════════════════════════════════════════════
 *  SCENARIO B:  Host = Windows  →  Guest = Linux ELF
 *  ─────────────────────────────────────────────────
 *  MSVC does NOT support x64 inline assembly (__asm is x86-32 only).
 *  So we use C-level wrapper functions here.  The actual register
 *  remapping trampoline lives in thunks_win.asm (assembled with MASM).
 *
 *  How it works conceptually:
 *    1. ELF binary calls a stub address (e.g. for "write" syscall)
 *    2. thunks_win.asm trampoline receives args in System V regs:
 *         RDI=fd, RSI=buf, RDX=count
 *    3. Trampoline remaps to Microsoft x64:
 *         RCX=fd, RDX=buf, R8=count, R9=0
 *    4. Trampoline calls our C thunk function below
 *    5. C thunk calls the actual Win32 API
 * ═══════════════════════════════════════════════════════════════════ */

#elif defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/*
 * thunk_write_win  —  Emulates Linux write() syscall on Windows
 * ─────────────────────────────────────────────────────────────
 * After the ASM trampoline remaps registers, this function receives
 * arguments in the standard Microsoft x64 ABI (RCX, RDX, R8, R9):
 *
 *   Original (System V):     After remapping (MS x64):
 *     RDI = fd          →      RCX = fd
 *     RSI = buffer      →      RDX = buffer
 *     RDX = count       →      R8  = count
 *
 * We then call WriteConsole / WriteFile to perform actual I/O.
 */
static int64_t thunk_write_win(int64_t fd,       /* Was RDI → now RCX  */
                               int64_t buffer,   /* Was RSI → now RDX  */
                               int64_t count,    /* Was RDX → now R8   */
                               int64_t unused)   /* R9 (unused)        */
{
    (void)unused;

    HANDLE hOut;
    DWORD  written = 0;

    /*
     * Map Linux file descriptor to Windows HANDLE:
     *   fd 0 → STD_INPUT_HANDLE
     *   fd 1 → STD_OUTPUT_HANDLE
     *   fd 2 → STD_ERROR_HANDLE
     */
    switch ((int)fd) {
        case 0:  hOut = GetStdHandle(STD_INPUT_HANDLE);  break;
        case 1:  hOut = GetStdHandle(STD_OUTPUT_HANDLE); break;
        case 2:  hOut = GetStdHandle(STD_ERROR_HANDLE);  break;
        default:
            printf("[thunk] write: unsupported fd=%lld\n", (long long)fd);
            return -1;
    }

    /*
     * Call WriteConsoleA — the Windows equivalent of write(fd, buf, count).
     * Arguments map to Microsoft x64 ABI naturally since we're in MSVC:
     *   RCX = hOut
     *   RDX = buffer
     *   R8  = count
     *   R9  = &written
     */
    BOOL ok = WriteConsoleA(
        hOut,                        /* Console handle                  */
        (const void*)buffer,         /* Data to write                   */
        (DWORD)count,                /* Number of bytes                 */
        &written,                    /* Bytes actually written          */
        NULL                         /* Reserved                        */
    );

    printf("[thunk] write: fd=%lld, buf=%p, count=%lld → wrote %lu bytes\n",
           (long long)fd, (void*)buffer, (long long)count,
           (unsigned long)written);

    return ok ? (int64_t)written : -1;
}

/*
 * thunk_exit_win  —  Emulates Linux exit_group() syscall on Windows
 * ─────────────────────────────────────────────────────────────────
 *   Original: RDI = exit_code  →  Remapped: RCX = exit_code
 */
static int64_t thunk_exit_win(int64_t exit_code,
                              int64_t unused1,
                              int64_t unused2,
                              int64_t unused3)
{
    (void)unused1; (void)unused2; (void)unused3;

    printf("[thunk] exit_group(%lld) → ExitProcess\n", (long long)exit_code);
    ExitProcess((UINT)exit_code);

    return 0;  /* Never reached */
}

/* ── Thunk table for Windows host ────────────────────────────────── */
static ThunkEntry win_thunks[] = {
    { "write",        thunk_write_win },
    { "exit_group",   thunk_exit_win  },
};
#define THUNK_COUNT (sizeof(win_thunks) / sizeof(win_thunks[0]))

#endif /* _WIN32 */


/* ═══════════════════════════════════════════════════════════════════
 *  Common lookup functions (both platforms)
 * ═══════════════════════════════════════════════════════════════════ */

const ThunkEntry* get_thunk_table(int *count)
{
#ifdef __linux__
    *count = (int)THUNK_COUNT;
    return linux_thunks;
#elif defined(_WIN32)
    *count = (int)THUNK_COUNT;
    return win_thunks;
#else
    *count = 0;
    return NULL;
#endif
}

thunk_fn_t find_thunk(const char *name)
{
    int count = 0;
    const ThunkEntry *table = get_thunk_table(&count);

    for (int i = 0; i < count; i++) {
        if (strcmp(table[i].name, name) == 0) {
            return table[i].thunk;
        }
    }
    return NULL;
}

void install_thunks(void *loaded_image, size_t image_size)
{
    /*
     * TODO (Step 5): Walk the PE import table or ELF GOT/PLT and
     * patch each foreign function reference with the corresponding
     * thunk address from our table.
     *
     * For now, this is a placeholder that prints what it would do.
     */
    (void)loaded_image;
    (void)image_size;

    int count = 0;
    const ThunkEntry *table = get_thunk_table(&count);

    printf("[thunks] %d ABI translation thunks available:\n", count);
    for (int i = 0; i < count; i++) {
        printf("  %-16s → %p\n", table[i].name, (void*)table[i].thunk);
    }
}
