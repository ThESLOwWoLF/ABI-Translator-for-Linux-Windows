/*
 * Omni-Exec — Step 3: ABI Translation Thunks (Header)
 * ─────────────────────────────────────────────────────
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │          x86-64 CALLING CONVENTION CHEAT SHEET                 │
 * ├──────────────┬──────────────────┬──────────────────────────────┤
 * │   Argument   │  Microsoft x64   │   System V (Linux) ABI      │
 * │              │   (Windows)      │                              │
 * ├──────────────┼──────────────────┼──────────────────────────────┤
 * │   1st arg    │      RCX         │        RDI                   │
 * │   2nd arg    │      RDX         │        RSI                   │
 * │   3rd arg    │      R8          │        RDX                   │
 * │   4th arg    │      R9          │        RCX                   │
 * │   Return     │      RAX         │        RAX                   │
 * │   Shadow     │  32 bytes on     │        None                  │
 * │   Space      │  stack required  │                              │
 * └──────────────┴──────────────────┴──────────────────────────────┘
 *
 * The thunks below bridge these two ABIs so that:
 *   - Windows PE code running on Linux can call "Windows API" stubs
 *     that internally invoke Linux syscalls.
 *   - Linux ELF code running on Windows can call "Linux syscall" stubs
 *     that internally invoke Win32 API functions.
 */

#ifndef OMNI_THUNKS_H
#define OMNI_THUNKS_H

#include <stdint.h>
#include <stddef.h>

/* ─── Thunk function type ─────────────────────────────────────────
 * Every thunk has a uniform signature:
 *   int64_t thunk(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4)
 *
 * This matches the max register-passed args on both ABIs (4 args).
 */
typedef int64_t (*thunk_fn_t)(int64_t, int64_t, int64_t, int64_t);

/* ─── Thunk table entry ───────────────────────────────────────────
 * Maps a "foreign" function name (e.g. "WriteFile" or "write")
 * to its host-side thunk implementation.
 */
typedef struct {
    const char  *name;       /* Foreign function name to intercept   */
    thunk_fn_t   thunk;      /* Host-side implementation             */
} ThunkEntry;

/* ─── Public API ──────────────────────────────────────────────────── */

/*
 * get_thunk_table
 *   Returns a pointer to the array of available thunks.
 *   `count` is set to the number of entries.
 */
const ThunkEntry* get_thunk_table(int *count);

/*
 * find_thunk
 *   Looks up a thunk by name. Returns the thunk function pointer,
 *   or NULL if not found.
 */
thunk_fn_t find_thunk(const char *name);

/*
 * install_thunks
 *   Patches a thunk table address into a loaded binary's import/GOT
 *   section. (Placeholder for future steps.)
 */
void install_thunks(void *loaded_image, size_t image_size);

#endif /* OMNI_THUNKS_H */
