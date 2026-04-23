#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function structure
typedef struct {
    const char   *name;        
    const char   *formula;
    const char   *c_code;
    const uint8_t *code;
    size_t        code_size;
} MathFunc;

// Machine code (Compiled for Windows ABI - arguments in RCX, RDX)
// Note: Even for square, it expects the first parameter in RCX instead of RDI.
static const uint8_t code_square[] = {
    0x89, 0xC8,                  // mov eax, ecx
    0x0F, 0xAF, 0xC1,           // imul eax, ecx
    0xC3                         // ret
};

static const uint8_t code_cube[] = {
    0x89, 0xC8,                  // mov eax, ecx
    0x0F, 0xAF, 0xC1,           // imul eax, ecx
    0x0F, 0xAF, 0xC1,           // imul eax, ecx
    0xC3                         // ret
};

static const uint8_t code_double[] = {
    0x8D, 0x04, 0x09,           // lea eax, [rcx+rcx]
    0xC3                         // ret
};

static const uint8_t code_add42[] = {
    0x8D, 0x41, 0x2A,           // lea eax, [rcx+42]
    0xC3                         // ret
};

static const uint8_t code_factorial[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x83, 0xF9, 0x01,              // cmp ecx, 1
    0x7E, 0x08,                    // jle +8
    // loop:
    0x0F, 0xAF, 0xC1,             // imul eax, ecx
    0xFF, 0xC9,                    // dec ecx
    0x83, 0xF9, 0x01,              // cmp ecx, 1
    0x7F, 0xF6,                    // jg -10
    // done:
    0xC3                           // ret
};

static MathFunc functions[] = {
    { "square",     "x * x",           "return x * x;",         code_square,     sizeof(code_square)     },
    { "cube",       "x * x * x",       "return x * x * x;",     code_cube,       sizeof(code_cube)       },
    { "double",     "x * 2",           "return x * 2;",         code_double,     sizeof(code_double)     },
    { "add42",      "x + 42",          "return x + 42;",        code_add42,      sizeof(code_add42)      },
    { "factorial",  "x!",             "int r=1; for(...) r*=i;", code_factorial,  sizeof(code_factorial)  },
};
#define NUM_FUNCTIONS (sizeof(functions) / sizeof(functions[0]))

// Function to align a value
static uint32_t align_up(uint32_t val, uint32_t align) {
    return (val + align - 1) & ~(align - 1);
}

// Writes a minimalistic Windows PE executable.
static int write_test_pe(const char *filename, const MathFunc *func)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) return -1;

    // --- PE File Structure Definitions (Minimalistic) ---
    
    // DOS Header (64 bytes)
    uint8_t dos_header[64] = {0};
    dos_header[0] = 0x4D; // 'M'
    dos_header[1] = 0x5A; // 'Z'
    // e_lfanew at offset 60, points to 64 (start of PE Signature)
    uint32_t e_lfanew = 64;
    memcpy(&dos_header[60], &e_lfanew, 4);
    
    // PE Signature (4 bytes)
    uint8_t pe_sig[4] = {0x50, 0x45, 0x00, 0x00}; // "PE\0\0"
    
    // COFF Header (20 bytes)
    uint16_t machine = 0x8664; // AMD64
    uint16_t num_sections = 1;
    uint32_t timedatestamp = 0;
    uint32_t ptr_symtab = 0;
    uint32_t num_syms = 0;
    uint16_t size_opt_hdr = 240; // PE32+ Optional Header size
    uint16_t characteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header PE32+ (240 bytes)
    uint8_t opt_hdr[240] = {0};
    uint16_t magic = 0x020B; // PE32+
    memcpy(&opt_hdr[0], &magic, 2);
    // ... skipping linker version
    uint32_t size_of_code = align_up(func->code_size, 512); // Padded size
    memcpy(&opt_hdr[4], &size_of_code, 4);
    
    uint32_t address_of_entry_point = 0x1000;
    memcpy(&opt_hdr[16], &address_of_entry_point, 4);
    uint32_t base_of_code = 0x1000;
    memcpy(&opt_hdr[20], &base_of_code, 4);
    
    uint64_t image_base = 0x140000000;
    memcpy(&opt_hdr[24], &image_base, 8);
    
    uint32_t section_alignment = 0x1000;
    memcpy(&opt_hdr[32], &section_alignment, 4);
    uint32_t file_alignment = 0x200;
    memcpy(&opt_hdr[36], &file_alignment, 4);
    
    // Set subsystem version (Windows 5.0)
    uint16_t major_subsys_ver = 5;
    memcpy(&opt_hdr[48], &major_subsys_ver, 2);
    
    uint32_t size_of_image = align_up(0x1000 + func->code_size, 0x1000); // Headers + MathCode
    memcpy(&opt_hdr[56], &size_of_image, 4);
    
    uint32_t size_of_headers = 0x200; // Total header size written to file
    memcpy(&opt_hdr[60], &size_of_headers, 4);
    
    uint16_t subsystem = 3; // IMAGE_SUBSYSTEM_WINDOWS_CUI
    memcpy(&opt_hdr[68], &subsystem, 2);

    // Section Table (40 bytes)
    uint8_t sec_hdr[40] = {0};
    memcpy(&sec_hdr[0], ".text", 5);
    uint32_t virtual_size = (uint32_t)func->code_size;
    memcpy(&sec_hdr[8], &virtual_size, 4);
    uint32_t virtual_addr = 0x1000;
    memcpy(&sec_hdr[12], &virtual_addr, 4);
    uint32_t size_raw_data = align_up(func->code_size, 0x200);
    memcpy(&sec_hdr[16], &size_raw_data, 4);
    uint32_t ptr_raw_data = 0x200; // Code goes right after headers at 512 boundary
    memcpy(&sec_hdr[20], &ptr_raw_data, 4);
    uint32_t sec_characteristics = 0x60000020; // ERX (Execute | Read | Contains Code)
    memcpy(&sec_hdr[36], &sec_characteristics, 4);

    // Write all headers (Total 64 + 4 + 20 + 240 + 40 = 368 bytes)
    fwrite(dos_header, 1, 64, fp);
    fwrite(pe_sig, 1, 4, fp);
    
    // Write COFF manually to avoid struct padding issues
    fwrite(&machine, 2, 1, fp);
    fwrite(&num_sections, 2, 1, fp);
    fwrite(&timedatestamp, 4, 1, fp);
    fwrite(&ptr_symtab, 4, 1, fp);
    fwrite(&num_syms, 4, 1, fp);
    fwrite(&size_opt_hdr, 2, 1, fp);
    fwrite(&characteristics, 2, 1, fp);
    
    fwrite(opt_hdr, 1, 240, fp);
    fwrite(sec_hdr, 1, 40, fp);
    
    // Pad to 512 (0x200) bytes
    uint8_t padding[144] = {0};
    fwrite(padding, 1, 0x200 - 368, fp);
    
    // Write actual machine code (at offset 0x200)
    fwrite(func->code, 1, func->code_size, fp);
    
    // Pad code to FileAlignment (0x200)
    uint32_t remaining = size_raw_data - func->code_size;
    if(remaining > 0) {
        uint8_t *code_pad = calloc(remaining, 1);
        fwrite(code_pad, 1, remaining, fp);
        free(code_pad);
    }
    
    fclose(fp);

    printf("[+] Created: %s\n", filename);
    printf("    Function : %s(x) = %s\n", func->name, func->formula);
    printf("    Target   : Windows PE (x86-64 executable)\n\n");
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("  Usage: create_test_pe.exe <function_name>\n");
        printf("  Valid functions: square, cube, double, add42, factorial, all\n");
        return 0;
    }

    if (strcmp(argv[1], "all") == 0) {
        for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
            char filename[256];
            sprintf(filename, "%s.exe", functions[i].name);
            write_test_pe(filename, &functions[i]);
        }
        return 0;
    }

    for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
        if (strcmp(functions[i].name, argv[1]) == 0) {
            char filename[256];
            sprintf(filename, "%s.exe", functions[i].name);
            return write_test_pe(filename, &functions[i]);
        }
    }
    
    printf("Unknown function.\n");
    return 1;
}
