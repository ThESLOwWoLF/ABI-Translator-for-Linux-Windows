/*
 * Omni-Exec — Step 2: Memory Allocator Test
 * -------------------------------------------
 * Quick smoke test that:
 *   1. Allocates executable memory
 *   2. Writes a tiny machine-code snippet (x86-64 "return 42")
 *   3. Calls it as a function to prove execution works
 *   4. Frees the memory
 *
 * Build:
 *   Windows:  cl test_memory.c omni_memory.c /Fe:test_memory.exe
 *   Linux:    gcc test_memory.c omni_memory.c -o test_memory
 *
 * Expected output:
 *   [omni-mem] <platform>: allocated 4096 bytes (RWX) at <addr>
 *   [test] Calling machine code at <addr>...
 *   [test] Return value = 42  ← proves code execution worked!
 *   [omni-mem] <platform>: freed memory at <addr>
 */

#include <stdio.h>
#include <string.h>
#include "omni_memory.h"

int main(void)
{
    /* Allocate one page of executable memory */
    size_t page_size = 4096;
    void *mem = allocate_executable_memory(page_size);

    if (!mem) {
        fprintf(stderr, "[test] Allocation failed!\n");
        return 1;
    }

    /*
     * Write a minimal x86-64 function into the buffer:
     *
     *   mov eax, 42    →  B8 2A 00 00 00
     *   ret            →  C3
     *
     * This is a complete, valid function that returns the integer 42.
     */
    unsigned char code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,   /* mov eax, 42 */
        0xC3                              /* ret          */
    };
    memcpy(mem, code, sizeof(code));

    /* Cast the memory to a function pointer and call it */
    typedef int (*func_t)(void);
    func_t fn = (func_t)mem;

    printf("[test] Calling machine code at %p...\n", mem);
    int result = fn();
    printf("[test] Return value = %d", result);

    if (result == 42) {
        printf("  <-- code execution works!\n");
    } else {
        printf("  <-- UNEXPECTED (expected 42)\n");
    }

    /* Clean up */
    free_executable_memory(mem, page_size);

    printf("[test] Step 2 verification complete.\n");
    return 0;
}
