/*
 * Omni-Exec — Step 2: Cross-Platform Memory Allocator (Implementation)
 * ----------------------------------------------------------------------
 * Uses preprocessor directives to select the correct OS-native API
 * for allocating memory with executable permissions.
 *
 * Build (this file is compiled together with your main loader):
 *   Windows:  cl omni_memory.c omni_loader.c /Fe:omni_exec.exe
 *   Linux:    gcc omni_memory.c omni_loader.c -o omni_exec
 */

#include "omni_memory.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ─── Platform-specific includes ──────────────────────────────────── */

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#elif defined(__linux__)
    #include <sys/mman.h>
    #include <errno.h>
#else
    #error "Omni-Exec: Unsupported platform. Only Windows and Linux are supported."
#endif


/* ─── allocate_executable_memory ──────────────────────────────────── */

void* allocate_executable_memory(size_t size)
{
    if (size == 0) {
        fprintf(stderr, "[omni-mem] Error: cannot allocate 0 bytes.\n");
        return NULL;
    }

#ifdef _WIN32
    /*
     * Windows path — VirtualAlloc
     * ────────────────────────────
     * MEM_COMMIT | MEM_RESERVE : allocate and commit pages in one call.
     * PAGE_EXECUTE_READWRITE   : the memory is readable, writable, AND
     *                            executable — needed so we can copy ELF
     *                            code into it, then jump to it.
     *
     * NOTE: In a production loader you would allocate as RW first,
     *       copy the code, then VirtualProtect() to RX.  For this
     *       prototype we use RWX for simplicity.
     */
    void *mem = VirtualAlloc(
        NULL,                           /* Let the OS choose the address  */
        size,                           /* Number of bytes                */
        MEM_COMMIT | MEM_RESERVE,       /* Allocate + commit              */
        PAGE_EXECUTE_READWRITE          /* RWX permissions                */
    );

    if (!mem) {
        fprintf(stderr, "[omni-mem] VirtualAlloc failed (error %lu).\n",
                GetLastError());
        return NULL;
    }

    printf("[omni-mem] Windows: allocated %zu bytes (RWX) at %p\n", size, mem);
    return mem;

#elif defined(__linux__)
    /*
     * Linux path — mmap
     * ──────────────────
     * PROT_READ | PROT_WRITE | PROT_EXEC : RWX permissions so we can
     *     copy PE code into the region and then execute it.
     * MAP_PRIVATE | MAP_ANONYMOUS : private mapping, not backed by a file.
     *
     * NOTE: Same caveat as above — a hardened loader would mprotect()
     *       to RX after the copy is done.
     */
    void *mem = mmap(
        NULL,                                       /* OS picks address   */
        size,                                       /* Number of bytes    */
        PROT_READ | PROT_WRITE | PROT_EXEC,         /* RWX permissions    */
        MAP_PRIVATE | MAP_ANONYMOUS,                 /* Private anon map   */
        -1,                                          /* No file descriptor */
        0                                            /* Offset (ignored)   */
    );

    if (mem == MAP_FAILED) {
        fprintf(stderr, "[omni-mem] mmap failed: %s\n", strerror(errno));
        return NULL;
    }

    printf("[omni-mem] Linux: allocated %zu bytes (RWX) at %p\n", size, mem);
    return mem;

#endif
}


/* ─── free_executable_memory ──────────────────────────────────────── */

void free_executable_memory(void *ptr, size_t size)
{
    if (!ptr) return;

#ifdef _WIN32
    /*
     * VirtualFree with MEM_RELEASE frees the entire region.
     * When using MEM_RELEASE, the size parameter must be 0.
     */
    (void)size;  /* Size is not needed for MEM_RELEASE */
    if (!VirtualFree(ptr, 0, MEM_RELEASE)) {
        fprintf(stderr, "[omni-mem] VirtualFree failed (error %lu).\n",
                GetLastError());
    } else {
        printf("[omni-mem] Windows: freed memory at %p\n", ptr);
    }

#elif defined(__linux__)
    /*
     * munmap requires the exact size that was originally mapped.
     */
    if (munmap(ptr, size) != 0) {
        fprintf(stderr, "[omni-mem] munmap failed: %s\n", strerror(errno));
    } else {
        printf("[omni-mem] Linux: freed %zu bytes at %p\n", size, ptr);
    }

#endif
}


/* ─── load_section_into_memory ────────────────────────────────────── */

void* load_section_into_memory(FILE *fp, long file_offset, size_t size)
{
    if (!fp) {
        fprintf(stderr, "[omni-mem] Error: NULL file pointer.\n");
        return NULL;
    }

    /* 1. Allocate executable memory */
    void *mem = allocate_executable_memory(size);
    if (!mem) return NULL;

    /* 2. Seek to the code section in the binary file */
    if (fseek(fp, file_offset, SEEK_SET) != 0) {
        fprintf(stderr, "[omni-mem] Error: failed to seek to offset 0x%lX.\n",
                file_offset);
        free_executable_memory(mem, size);
        return NULL;
    }

    /* 3. Read the code section into our executable buffer */
    size_t bytes_read = fread(mem, 1, size, fp);
    if (bytes_read != size) {
        fprintf(stderr,
                "[omni-mem] Warning: requested %zu bytes, read %zu bytes.\n",
                size, bytes_read);
        /*
         * Zero-fill the remainder — this handles the common case where
         * SizeOfRawData < VirtualSize (BSS-like padding in PE files).
         */
        memset((char*)mem + bytes_read, 0, size - bytes_read);
    }

    printf("[omni-mem] Loaded %zu bytes from file offset 0x%lX into %p\n",
           bytes_read, file_offset, mem);

    return mem;
}
