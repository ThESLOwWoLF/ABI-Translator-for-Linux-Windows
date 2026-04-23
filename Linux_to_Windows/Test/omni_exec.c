/*
 * Omni-Exec — Step 4: The Execution Jump
 * ────────────────────────────────────────
 * This is the final integration point.  It demonstrates:
 *
 *   1. Casting a void* (raw memory address) to a function pointer
 *   2. Calling the function pointer to execute foreign code
 *   3. Passing arguments through the function pointer
 *   4. Retrieving a return value from the executed code
 *
 * This file also serves as a combined test for Steps 2–4:
 *   - Allocates executable memory          (Step 2: omni_memory)
 *   - Lists available ABI thunks           (Step 3: omni_thunks)
 *   - Writes machine code, casts, jumps    (Step 4: execution jump)
 *
 * Build:
 *   Windows:  cl omni_exec.c omni_memory.c omni_thunks.c /Fe:omni_exec.exe /W4
 *   Linux:    gcc omni_exec.c omni_memory.c omni_thunks.c -o omni_exec
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "omni_memory.h"
#include "omni_thunks.h"

/* ═══════════════════════════════════════════════════════════════════
 *  STEP 4:  Function pointer types for the execution jump
 * ═══════════════════════════════════════════════════════════════════
 *
 * The entry point of any loaded binary is just a memory address.
 * To call it from C, we cast that void* to a typed function pointer.
 *
 * Different binaries have different signatures, so we define a few
 * common prototypes:
 */

/*
 * Type 1:  void entry(void)
 *   Simplest case — no arguments, no return value.
 *   Typical for _start in minimal ELF binaries.
 */
typedef void (*entry_void_t)(void);

/*
 * Type 2:  int entry(int arg)
 *   Takes one integer argument, returns an integer.
 *   Useful for testing: pass a number in, get a result back.
 */
typedef int (*entry_int_t)(int);

/*
 * Type 3:  int entry(int arg1, int arg2)
 *   Two arguments — for arithmetic test functions.
 */
typedef int (*entry_int2_t)(int, int);

/*
 * Type 4:  int main(int argc, char **argv)
 *   Standard C main signature — used when jumping to a
 *   full program's entry point.
 */
typedef int (*entry_main_t)(int, char**);


/* ═══════════════════════════════════════════════════════════════════
 *  execute_at — The core "jump" function
 * ═══════════════════════════════════════════════════════════════════
 *
 * This function takes a void* pointing to executable machine code,
 * casts it to a function pointer, calls it with the given argument,
 * and returns the result.
 *
 * This is the fundamental mechanism of any binary loader:
 *   void*  →  function pointer  →  CALL instruction  →  result
 */
static int execute_at(void *code_address, int argument)
{
    printf("[exec] Casting %p to function pointer...\n", code_address);

    /*
     * THE EXECUTION JUMP
     * ──────────────────
     * This single line is the heart of Omni-Exec:
     *
     *   1. (entry_int_t) casts the raw void* to a typed function pointer
     *   2. The compiler emits a CALL instruction to that address
     *   3. `argument` is placed in the correct register per the host ABI
     *      (RCX on Windows, RDI on Linux)
     *   4. The return value comes back in RAX on both platforms
     */
    entry_int_t fn = (entry_int_t)code_address;

    printf("[exec] Jumping to code with argument = %d...\n", argument);

    int result = fn(argument);

    printf("[exec] Code returned: %d\n", result);
    return result;
}


/* ═══════════════════════════════════════════════════════════════════
 *  Test machine code snippets (x86-64)
 *  ───────────────────────────────────
 *  These are raw x86-64 instruction bytes that we write into
 *  executable memory and then jump to.
 * ═══════════════════════════════════════════════════════════════════ */

/*
 * test_return_42  —  "mov eax, 42; ret"
 *   Ignores arguments, always returns 42.
 *   Verifies basic code execution.
 */
static unsigned char code_return_42[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,   /* mov eax, 42  */
    0xC3                              /* ret           */
};

/*
 * test_double  —  doubles the input argument
 *
 * On Windows (MSVC), first arg is in ECX:
 *   lea eax, [rcx + rcx]    →  8D 04 09
 *   ret                     →  C3
 *
 * On Linux (GCC), first arg is in EDI:
 *   lea eax, [rdi + rdi]    →  8D 04 3F
 *   ret                     →  C3
 */
#ifdef _WIN32
static unsigned char code_double[] = {
    0x8D, 0x04, 0x09,               /* lea eax, [rcx+rcx]  (Windows) */
    0xC3                              /* ret                           */
};
#elif defined(__linux__)
static unsigned char code_double[] = {
    0x8D, 0x04, 0x3F,               /* lea eax, [rdi+rdi]  (Linux)   */
    0xC3                              /* ret                           */
};
#endif

/*
 * test_multiply  —  arg * 7
 *
 * Windows (first arg in ECX):
 *   imul eax, ecx, 7   →  6B C1 07
 *   ret                 →  C3
 *
 * Linux (first arg in EDI):
 *   imul eax, edi, 7   →  6B C7 07
 *   ret                 →  C3
 */
#ifdef _WIN32
static unsigned char code_multiply_7[] = {
    0x6B, 0xC1, 0x07,               /* imul eax, ecx, 7   (Windows)  */
    0xC3                              /* ret                           */
};
#elif defined(__linux__)
static unsigned char code_multiply_7[] = {
    0x6B, 0xC7, 0x07,               /* imul eax, edi, 7   (Linux)    */
    0xC3                              /* ret                           */
};
#endif

/*
 * test_add_square  —  arg + arg*arg  (i.e., n + n²)
 *
 * Windows (ECX = n):
 *   mov  eax, ecx      →  89 C8
 *   imul eax, ecx      →  0F AF C1
 *   add  eax, ecx      →  01 C8
 *   ret                 →  C3
 *
 * Linux (EDI = n):
 *   mov  eax, edi      →  89 F8
 *   imul eax, edi      →  0F AF C7
 *   add  eax, edi      →  01 F8
 *   ret                 →  C3
 */
#ifdef _WIN32
static unsigned char code_add_square[] = {
    0x89, 0xC8,                      /* mov eax, ecx                  */
    0x0F, 0xAF, 0xC1,               /* imul eax, ecx                 */
    0x01, 0xC8,                      /* add eax, ecx                  */
    0xC3                              /* ret                           */
};
#elif defined(__linux__)
static unsigned char code_add_square[] = {
    0x89, 0xF8,                      /* mov eax, edi                  */
    0x0F, 0xAF, 0xC7,               /* imul eax, edi                 */
    0x01, 0xF8,                      /* add eax, edi                  */
    0xC3                              /* ret                           */
};
#endif


/* ═══════════════════════════════════════════════════════════════════
 *  run_code_test — Helper to run one machine code test
 * ═══════════════════════════════════════════════════════════════════ */
static int run_code_test(const char *name,
                         unsigned char *code, size_t code_size,
                         int input, int expected)
{
    size_t page_size = 4096;

    /* Step 2: Allocate executable memory */
    void *mem = allocate_executable_memory(page_size);
    if (!mem) return 0;

    /* Copy machine code into executable buffer */
    memcpy(mem, code, code_size);

    /* Step 4: Execute the code */
    printf("\n──── Test: %s ────\n", name);
    int result = execute_at(mem, input);

    /* Verify */
    int passed = (result == expected);
    printf("[test] Input=%d  Expected=%d  Got=%d  → %s\n",
           input, expected, result,
           passed ? "PASS" : "FAIL");

    /* Cleanup */
    free_executable_memory(mem, page_size);
    return passed;
}


/* ═══════════════════════════════════════════════════════════════════
 *  main — Run all tests
 * ═══════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("==============================================\n");
    printf("  Omni-Exec :: Steps 2-4 Integration Test\n");
    printf("==============================================\n");

    /* ── Step 3: Show available thunks ─────────────────────── */
    printf("\n── Step 3: ABI Translation Thunks ──\n");
    install_thunks(NULL, 0);

    /* ── Step 4: Execution Jump Tests ─────────────────────── */
    printf("\n── Step 4: Execution Jump Tests ──\n");

    int total = 0, passed = 0;

    /* Test 1: Return constant 42 */
    total++;
    passed += run_code_test(
        "Return 42 (no args)",
        code_return_42, sizeof(code_return_42),
        0,      /* input (ignored) */
        42      /* expected output */
    );

    /* Test 2: Double the input — double(21) = 42 */
    total++;
    passed += run_code_test(
        "Double input: f(21) = 42",
        code_double, sizeof(code_double),
        21,     /* input  */
        42      /* expected */
    );

    /* Test 3: Multiply by 7 — f(6) = 42 */
    total++;
    passed += run_code_test(
        "Multiply by 7: f(6) = 42",
        code_multiply_7, sizeof(code_multiply_7),
        6,      /* input  */
        42      /* expected */
    );

    /* Test 4: n + n² — f(5) = 5 + 25 = 30 */
    total++;
    passed += run_code_test(
        "n + n^2: f(5) = 30",
        code_add_square, sizeof(code_add_square),
        5,      /* input  */
        30      /* expected */
    );

    /* ── Summary ──────────────────────────────────────────── */
    printf("\n==============================================\n");
    printf("  Results: %d / %d tests passed\n", passed, total);
    printf("==============================================\n");

    return (passed == total) ? 0 : 1;
}
