// pe_loader.c — Windows PE on Linux reverse loader
// This must be compiled and run on Linux/WSL:
// gcc pe_loader.c -o pe_loader
// Usage: ./pe_loader <windows-exe-file> <arg>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h> // Linux memory mapping

// ---------------------------------------------------------
// Minimal PE structures required for parsing
// ---------------------------------------------------------

typedef struct {
    uint8_t  e_magic[2];      // "MZ"
    uint8_t  padding_1[58];
    uint32_t e_lfanew;        // Offset to PE signature
} DOS_Header;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_Header;

typedef struct {
    uint16_t Magic;           // 0x010B (PE32) or 0x020B (PE32+)
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint; // The RVA of the entry point!
    uint32_t BaseOfCode;
    // Note: Structure diverges for PE32 vs PE32+ after this point.
    // We only care about AddressOfEntryPoint and SizeOfHeaders.
} Optional_Header;

typedef struct {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} Section_Header;

int main(int argc, char *argv[]) {
    printf("==============================================\n");
    printf("  Omni-Exec :: PE-on-Linux Loader\n");
    printf("==============================================\n\n");

    if (argc < 3) {
        printf("  Usage: ./pe_loader <windows.exe> <integer>\n");
        return 1;
    }

    const char *pe_path = argv[1];
    int user_arg = atoi(argv[2]);

    printf("-- Step 1: Parse PE Binary --\n\n");

    FILE *fp = fopen(pe_path, "rb");
    if (!fp) {
        fprintf(stderr, "  [!] Cannot open %s\n", pe_path);
        return 1;
    }

    DOS_Header dos;
    if (fread(&dos, sizeof(DOS_Header), 1, fp) != 1 || dos.e_magic[0] != 'M' || dos.e_magic[1] != 'Z') {
        fprintf(stderr, "  [!] Not a valid Windows PE file (missing MZ).\n");
        return 1;
    }

    fseek(fp, dos.e_lfanew, SEEK_SET);
    uint32_t pe_sig;
    fread(&pe_sig, 4, 1, fp);
    if (pe_sig != 0x00004550) { // "PE\0\0"
        fprintf(stderr, "  [!] Invalid PE signature.\n");
        return 1;
    }

    COFF_Header coff;
    fread(&coff, sizeof(COFF_Header), 1, fp);

    if (coff.Machine != 0x8664) {
        fprintf(stderr, "  [!] Not a 64-bit AMD64 PE file.\n");
        return 1;
    }

    long opt_start = ftell(fp);
    Optional_Header opt;
    fread(&opt, sizeof(Optional_Header), 1, fp);

    printf("  Format       : Windows PE32+ (x86-64)\n");
    printf("  Entry (RVA)  : 0x%X\n", opt.AddressOfEntryPoint);
    printf("  Sections     : %d\n\n", coff.NumberOfSections);

    // Find .text section
    fseek(fp, opt_start + coff.SizeOfOptionalHeader, SEEK_SET);
    Section_Header text_sec;
    int found_text = 0;

    for (int i = 0; i < coff.NumberOfSections; i++) {
        Section_Header sec;
        fread(&sec, sizeof(Section_Header), 1, fp);
        if (strncmp((char*)sec.Name, ".text", 5) == 0 || (sec.Characteristics & 0x20000000)) { // Contains code
            text_sec = sec;
            found_text = 1;
            break;
        }
    }

    if (!found_text) {
        fprintf(stderr, "  [!] Could not find executable code section.\n");
        return 1;
    }

    printf("  Code Section : %.*s\n", 8, text_sec.Name);
    printf("    Raw Offset : 0x%X\n", text_sec.PointerToRawData);
    printf("    Copy Size  : %u bytes\n\n", text_sec.SizeOfRawData);

    // ---------------------------------------------------------
    // Step 2: Load into Executable Memory
    // ---------------------------------------------------------
    printf("-- Step 2: Allocate Executable Memory (Linux mmap) --\n\n");

    // Allocate readable, writable, EXECUTABLE memory on Linux
    void *exec_mem = mmap(NULL, text_sec.SizeOfRawData,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED) {
        fprintf(stderr, "  [!] mmap failed!\n");
        return 1;
    }

    fseek(fp, text_sec.PointerToRawData, SEEK_SET);
    fread(exec_mem, 1, text_sec.SizeOfRawData, fp);
    fclose(fp);

    printf("  Loaded at    : %p\n", exec_mem);

    // Calculate actual entry pointer inside the loaded segment
    // EntryPoint is an RVA relative to ImageBase. The .text section is ALSO at an RVA.
    // Offset in .text = Entry RVA - .text RVA
    uint32_t entry_offset = opt.AddressOfEntryPoint - text_sec.VirtualAddress;
    void *entry_point = (char*)exec_mem + entry_offset;

    printf("  Entry address: %p\n\n", entry_point);

    // ---------------------------------------------------------
    // Step 3 & 4: ABI Translation & Execution
    // ---------------------------------------------------------
    printf("-- Step 3 & 4: ABI Trampoline & Execute! --\n\n");

    // GCC magic: By casting the pointer with __attribute__((ms_abi)),
    // the Linux GCC compiler will AUTOMATICALLY generate the trampoline for us!
    // It will translate our System V args (RDI) into Windows args (RCX) 
    // before making the CPU call instruction.
    
    typedef int __attribute__((ms_abi)) (*windows_math_fn_t)(int);
    
    windows_math_fn_t fn = (windows_math_fn_t)entry_point;

    printf("  Executing Windows .exe code on Linux...\n");
    int result = fn(user_arg);

    printf("  Result: %d\n\n", result);

    munmap(exec_mem, text_sec.SizeOfRawData);

    printf("-- Done --\n\n");
    return 0;
}
