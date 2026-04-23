;
; Omni-Exec — Step 3: Windows ASM Trampoline (MASM / x86-64)
; ─────────────────────────────────────────────────────────────
; MSVC does NOT support inline assembly for x86-64 targets.
; This file provides the low-level register remapping trampolines
; that receive arguments in the Linux System V ABI and remap them
; to the Microsoft x64 ABI before calling the C thunk functions.
;
; Build (integrated with MSVC):
;   ml64 /c thunks_win.asm
;   cl omni_exec.c omni_thunks.c omni_memory.c thunks_win.obj /Fe:omni_exec.exe
;
; ─────────────────────────────────────────────────────────────
;  Register mapping:
;
;  System V (incoming)     Microsoft x64 (outgoing)
;  ────────────────────    ────────────────────────
;  RDI  = arg1         →  RCX = arg1
;  RSI  = arg2         →  RDX = arg2
;  RDX  = arg3         →  R8  = arg3
;  RCX  = arg4         →  R9  = arg4
; ─────────────────────────────────────────────────────────────

.CODE

; ── sysv_to_ms_trampoline ────────────────────────────────────
; Generic trampoline that:
;   1. Receives 4 arguments in System V registers (RDI, RSI, RDX, RCX)
;   2. Remaps them to Microsoft x64 registers (RCX, RDX, R8, R9)
;   3. Jumps to the target function (address passed in RAX)
;
; Usage: Load the target C thunk address into RAX before calling.
;        The ELF binary's patched GOT entry would point here.
;
PUBLIC sysv_to_ms_trampoline
sysv_to_ms_trampoline PROC

    ; ── Save the target function address (already in RAX) ────
    mov  r10, rax           ; R10 = target (temp, not arg register)

    ; ── Remap: System V  →  Microsoft x64 ───────────────────
    ;    We must be careful about ordering since RDX and RCX
    ;    are used in BOTH ABIs (but for different argument slots).

    mov  r9,  rcx           ; R9  ← arg4 (was RCX in SysV)
    mov  r8,  rdx           ; R8  ← arg3 (was RDX in SysV)
    mov  rdx, rsi           ; RDX ← arg2 (was RSI in SysV)
    mov  rcx, rdi           ; RCX ← arg1 (was RDI in SysV)

    ; ── Allocate shadow space (32 bytes, required by MS x64) ─
    sub  rsp, 28h           ; 32 bytes shadow + 8 for alignment

    ; ── Call the target C function ───────────────────────────
    call r10

    ; ── Clean up shadow space ────────────────────────────────
    add  rsp, 28h

    ; ── Return (RAX already has the result) ──────────────────
    ret

sysv_to_ms_trampoline ENDP

END
