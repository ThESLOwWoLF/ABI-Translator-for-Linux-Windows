/*
 * Omni-Exec — Step 2: Cross-Platform Memory Allocator (Header)
 * --------------------------------------------------------------
 * Provides a unified API for allocating/freeing executable memory
 * on both Windows and Linux hosts.
 */

#ifndef OMNI_MEMORY_H
#define OMNI_MEMORY_H

#include <stddef.h>  /* size_t */
#include <stdio.h>   /* FILE   */

/*
 * allocate_executable_memory
 *   Allocates `size` bytes of memory with Read + Write + Execute
 *   permissions. Returns NULL on failure.
 *
 *   - Linux  : backed by mmap()        with PROT_READ|PROT_WRITE|PROT_EXEC
 *   - Windows: backed by VirtualAlloc() with PAGE_EXECUTE_READWRITE
 */
void* allocate_executable_memory(size_t size);

/*
 * free_executable_memory
 *   Releases memory previously obtained from allocate_executable_memory().
 *   `size` must match the original allocation size (required by munmap on Linux).
 */
void free_executable_memory(void *ptr, size_t size);

/*
 * load_section_into_memory
 *   Convenience function: allocates executable memory of `size` bytes,
 *   then copies `size` bytes from file `fp` starting at `file_offset`
 *   into the allocated region.
 *
 *   Returns pointer to the loaded code, or NULL on failure.
 *   On success, the caller is responsible for calling
 *   free_executable_memory() with the same size.
 */
void* load_section_into_memory(FILE *fp, long file_offset, size_t size);

#endif /* OMNI_MEMORY_H */
