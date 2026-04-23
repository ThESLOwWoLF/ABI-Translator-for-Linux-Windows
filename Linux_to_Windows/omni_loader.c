// Omni-Exec — Unified ELF-on-Windows Loader
// Usage: omni_loader.exe <elf-file> <integer-argument>
// Build: cl omni_loader.c omni_memory.c /Fe:omni_loader.exe

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "omni_memory.h"

// Minimal ELF64 structures
#define ELF_MAGIC   "\x7F""ELF"
#define ELFCLASS64  2
#define PT_LOAD     1
#define PF_X        0x1

typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;       // Entry point virtual address
    uint64_t e_phoff;       // Program header table offset
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;       // Number of program headers
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;        // Segment type (PT_LOAD = loadable)
    uint32_t p_flags;       // Segment flags (PF_X = executable)
    uint64_t p_offset;      // File offset of segment
    uint64_t p_vaddr;       // Virtual address in memory
    uint64_t p_paddr;
    uint64_t p_filesz;      // Size in file
    uint64_t p_memsz;       // Size in memory
    uint64_t p_align;
} Elf64_Phdr;

// ABI Trampoline: remaps Microsoft x64 registers -> System V registers
// RCX->RDI, RDX->RSI, R8->RDX, R9->RCX, then jumps to ELF code
#define TRAMPOLINE_SIZE  24
#define TARGET_ADDR_OFFSET 14

static uint8_t trampoline_template[TRAMPOLINE_SIZE] = {
    0x48, 0x89, 0xCF,                   // mov rdi, rcx
    0x48, 0x89, 0xD6,                   // mov rsi, rdx
    0x4C, 0x89, 0xC2,                   // mov rdx, r8
    0x4C, 0x89, 0xC9,                   // mov rcx, r9
    0x48, 0xB8, 0,0,0,0,0,0,0,0,       // movabs rax, <target_addr>
    0xFF, 0xE0                           // jmp rax
};

int main(int argc, char *argv[])
{
    printf("==============================================\n");
    printf("  Omni-Exec :: ELF-on-Windows Loader\n");
    printf("==============================================\n\n");

    if (argc < 3) {
        printf("  Usage: %s <elf-file> <integer-argument>\n\n", argv[0]);
        return 1;
    }

    const char *elf_path = argv[1];
    int user_arg = atoi(argv[2]);

    // Step 1: Parse ELF Binary
    printf("-- Step 1: Parse ELF Binary --\n\n");

    FILE *fp = fopen(elf_path, "rb");
    if (!fp) {
        fprintf(stderr, "  [!] Cannot open file: %s\n", elf_path);
        return 1;
    }

    uint8_t magic[4];
    if (fread(magic, 1, 4, fp) != 4) {
        fprintf(stderr, "  [!] File too small.\n");
        fclose(fp);
        return 1;
    }

    if (memcmp(magic, ELF_MAGIC, 4) != 0) {
        if (magic[0] == 'M' && magic[1] == 'Z')
            fprintf(stderr, "  [!] This is a Windows PE file, not a Linux ELF.\n");
        else
            fprintf(stderr, "  [!] Unknown format (magic: %02X %02X %02X %02X)\n",
                    magic[0], magic[1], magic[2], magic[3]);
        fclose(fp);
        return 1;
    }

    rewind(fp);
    Elf64_Ehdr ehdr;
    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) {
        fprintf(stderr, "  [!] Failed to read ELF header.\n");
        fclose(fp);
        return 1;
    }

    if (ehdr.e_ident[4] != ELFCLASS64 || ehdr.e_machine != 0x3E) {
        fprintf(stderr, "  [!] Not a 64-bit x86-64 ELF.\n");
        fclose(fp);
        return 1;
    }

    printf("  File           : %s\n", elf_path);
    printf("  Format         : Linux ELF64 (x86-64)\n");
    printf("  Entry point    : 0x%llX\n", (unsigned long long)ehdr.e_entry);
    printf("  Program headers: %u\n\n", ehdr.e_phnum);

    // Find executable PT_LOAD segment
    fseek(fp, (long)ehdr.e_phoff, SEEK_SET);
    Elf64_Phdr exec_phdr;
    int found = 0;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, fp) != 1) break;
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            exec_phdr = phdr;
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "  [!] No executable segment found.\n");
        fclose(fp);
        return 1;
    }

    printf("  Executable segment:\n");
    printf("    File offset  : 0x%llX\n", (unsigned long long)exec_phdr.p_offset);
    printf("    Virtual addr : 0x%llX\n", (unsigned long long)exec_phdr.p_vaddr);
    printf("    Size         : %llu bytes\n\n", (unsigned long long)exec_phdr.p_filesz);

    // Step 2: Load code into executable memory
    printf("-- Step 2: Load into Executable Memory --\n\n");

    size_t load_size = (size_t)exec_phdr.p_filesz;
    void *loaded_code = load_section_into_memory(fp, (long)exec_phdr.p_offset, load_size);
    fclose(fp);

    if (!loaded_code) {
        fprintf(stderr, "  [!] Failed to load code.\n");
        return 1;
    }

    uint64_t entry_offset = ehdr.e_entry - exec_phdr.p_vaddr;
    void *entry_point = (char*)loaded_code + entry_offset;

    printf("  Loaded at      : %p\n", loaded_code);
    printf("  Entry address  : %p\n\n", entry_point);

    // Step 3: Build ABI Trampoline
    printf("-- Step 3: Build ABI Trampoline --\n\n");
    printf("  Remapping: RCX->RDI, RDX->RSI, R8->RDX, R9->RCX\n\n");

    void *tramp_mem = allocate_executable_memory(4096);
    if (!tramp_mem) {
        free_executable_memory(loaded_code, load_size);
        return 1;
    }

    memcpy(tramp_mem, trampoline_template, TRAMPOLINE_SIZE);
    uint64_t target_addr = (uint64_t)(uintptr_t)entry_point;
    memcpy((uint8_t*)tramp_mem + TARGET_ADDR_OFFSET, &target_addr, 8);

    // Step 4: Execute
    printf("-- Step 4: Execute --\n\n");
    printf("  Calling ELF code with argument: %d\n", user_arg);

    typedef int (*math_func_t)(int);
    math_func_t fn = (math_func_t)tramp_mem;

    int result = fn(user_arg);

    printf("  Result: %d\n\n", result);

    free_executable_memory(tramp_mem, 4096);
    free_executable_memory(loaded_code, load_size);

    printf("-- Done --\n\n");
    return 0;
}
