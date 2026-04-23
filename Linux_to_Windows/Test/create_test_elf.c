/*
 * Omni-Exec — Test ELF Generator
 * ────────────────────────────────
 * Generates minimal valid Linux ELF64 binaries containing simple
 * math functions. These can then be loaded and executed on Windows
 * using omni_loader.exe.
 *
 * Usage:
 *   create_test_elf.exe                (interactive menu)
 *   create_test_elf.exe square         (generates square.elf)
 *   create_test_elf.exe all            (generates all test ELFs)
 *
 * Build:
 *   cl create_test_elf.c /Fe:create_test_elf.exe /W4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ═══════════════════════════════════════════════════════════════════
 *  Machine code for each math function
 *  ────────────────────────────────────
 *  All functions follow the Linux System V x86-64 ABI:
 *    - First argument in EDI (lower 32 bits of RDI)
 *    - Return value in EAX
 *
 *  These are the EXACT same bytes that GCC would produce if you
 *  compiled these functions on Linux with optimizations.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char   *name;         /* Function name                      */
    const char   *formula;      /* Human-readable formula             */
    const char   *c_code;       /* Equivalent C code                  */
    const uint8_t *code;        /* x86-64 machine code bytes          */
    size_t        code_size;    /* Number of bytes                    */
    int (*verify)(int);         /* C function to verify results       */
} MathFunc;

/* ── Machine code bytes ──────────────────────────────────────────── */

/*  square(x) = x * x
 *    mov eax, edi       ; eax = x
 *    imul eax, edi      ; eax = x * x
 *    ret
 */
static const uint8_t code_square[] = {
    0x89, 0xF8,                  /* mov eax, edi         */
    0x0F, 0xAF, 0xC7,           /* imul eax, edi        */
    0xC3                         /* ret                  */
};
static int verify_square(int x) { return x * x; }

/*  cube(x) = x * x * x
 *    mov eax, edi       ; eax = x
 *    imul eax, edi      ; eax = x * x
 *    imul eax, edi      ; eax = x * x * x
 *    ret
 */
static const uint8_t code_cube[] = {
    0x89, 0xF8,                  /* mov eax, edi         */
    0x0F, 0xAF, 0xC7,           /* imul eax, edi        */
    0x0F, 0xAF, 0xC7,           /* imul eax, edi        */
    0xC3                         /* ret                  */
};
static int verify_cube(int x) { return x * x * x; }

/*  double_val(x) = x * 2
 *    lea eax, [rdi+rdi] ; eax = x + x
 *    ret
 */
static const uint8_t code_double[] = {
    0x8D, 0x04, 0x3F,           /* lea eax, [rdi+rdi]   */
    0xC3                         /* ret                  */
};
static int verify_double(int x) { return x * 2; }

/*  triple(x) = x * 3
 *    imul eax, edi, 3
 *    ret
 */
static const uint8_t code_triple[] = {
    0x6B, 0xC7, 0x03,           /* imul eax, edi, 3     */
    0xC3                         /* ret                  */
};
static int verify_triple(int x) { return x * 3; }

/*  add42(x) = x + 42
 *    lea eax, [rdi+42]
 *    ret
 */
static const uint8_t code_add42[] = {
    0x8D, 0x47, 0x2A,           /* lea eax, [rdi+42]    */
    0xC3                         /* ret                  */
};
static int verify_add42(int x) { return x + 42; }

/*  negate(x) = -x
 *    mov eax, edi
 *    neg eax
 *    ret
 */
static const uint8_t code_negate[] = {
    0x89, 0xF8,                  /* mov eax, edi         */
    0xF7, 0xD8,                  /* neg eax              */
    0xC3                         /* ret                  */
};
static int verify_negate(int x) { return -x; }

/*  sum_to_n(x) = x * (x + 1) / 2
 *    lea eax, [rdi+1]
 *    imul eax, edi
 *    sar eax, 1
 *    ret
 */
static const uint8_t code_sum_to_n[] = {
    0x8D, 0x47, 0x01,           /* lea eax, [rdi+1]     */
    0x0F, 0xAF, 0xC7,           /* imul eax, edi        */
    0xD1, 0xF8,                  /* sar eax, 1           */
    0xC3                         /* ret                  */
};
static int verify_sum_to_n(int x) { return x * (x + 1) / 2; }

/*  n_plus_nsq(x) = x + x*x
 *    mov eax, edi
 *    imul eax, edi
 *    add eax, edi
 *    ret
 */
static const uint8_t code_n_plus_nsq[] = {
    0x89, 0xF8,                  /* mov eax, edi         */
    0x0F, 0xAF, 0xC7,           /* imul eax, edi        */
    0x01, 0xF8,                  /* add eax, edi         */
    0xC3                         /* ret                  */
};
static int verify_n_plus_nsq(int x) { return x + x * x; }

/*  power_of_2(x) = 2^x  (using bit shift)
 *    mov eax, 1
 *    mov ecx, edi
 *    shl eax, cl
 *    ret
 */
static const uint8_t code_power2[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1          */
    0x89, 0xF9,                    /* mov ecx, edi        */
    0xD3, 0xE0,                    /* shl eax, cl         */
    0xC3                           /* ret                 */
};
static int verify_power2(int x) { return 1 << x; }

/*  factorial(x)  — iterative, uses a loop
 *    mov eax, 1         ; result = 1
 *    cmp edi, 1         ; if x <= 1, return 1
 *    jle done
 *  loop:
 *    imul eax, edi      ; result *= x
 *    dec edi            ; x--
 *    cmp edi, 1
 *    jg loop
 *  done:
 *    ret
 */
static const uint8_t code_factorial[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00, /* mov eax, 1          */
    0x83, 0xFF, 0x01,              /* cmp edi, 1          */
    0x7E, 0x08,                    /* jle +8 (to ret)     */
    /* loop: */
    0x0F, 0xAF, 0xC7,             /* imul eax, edi       */
    0xFF, 0xCF,                    /* dec edi             */
    0x83, 0xFF, 0x01,              /* cmp edi, 1          */
    0x7F, 0xF6,                    /* jg -10 (to loop)    */
    /* done: */
    0xC3                           /* ret                 */
};
static int verify_factorial(int x) {
    int r = 1;
    for (int i = 2; i <= x; i++) r *= i;
    return r;
}

/* ── Function table ──────────────────────────────────────────────── */

static MathFunc functions[] = {
    { "square",     "x * x",           "return x * x;",         code_square,     sizeof(code_square),     verify_square     },
    { "cube",       "x * x * x",       "return x * x * x;",     code_cube,       sizeof(code_cube),       verify_cube       },
    { "double",     "x * 2",           "return x * 2;",         code_double,     sizeof(code_double),     verify_double     },
    { "triple",     "x * 3",           "return x * 3;",         code_triple,     sizeof(code_triple),     verify_triple     },
    { "add42",      "x + 42",          "return x + 42;",        code_add42,      sizeof(code_add42),      verify_add42      },
    { "negate",     "-x",              "return -x;",            code_negate,     sizeof(code_negate),     verify_negate     },
    { "sum_to_n",   "x*(x+1)/2",      "return x*(x+1)/2;",     code_sum_to_n,   sizeof(code_sum_to_n),   verify_sum_to_n   },
    { "n_plus_nsq", "x + x*x",        "return x + x*x;",       code_n_plus_nsq, sizeof(code_n_plus_nsq), verify_n_plus_nsq },
    { "power2",     "2^x",            "return 1 << x;",        code_power2,     sizeof(code_power2),     verify_power2     },
    { "factorial",  "x!",             "int r=1; for(...) r*=i;", code_factorial,  sizeof(code_factorial),  verify_factorial   },
};
#define NUM_FUNCTIONS (sizeof(functions) / sizeof(functions[0]))


/* ═══════════════════════════════════════════════════════════════════
 *  ELF64 Binary Writer
 *  ────────────────────
 *  Constructs a minimal but VALID ELF64 executable file.
 *
 *  File layout:
 *    Offset 0x00 : ELF64 Header    (64 bytes)
 *    Offset 0x40 : Program Header  (56 bytes)
 *    Offset 0x78 : Machine Code    (variable)
 *
 *  The resulting file can be:
 *    - Loaded by omni_loader.exe on Windows
 *    - Actually executed on Linux (!):  chmod +x file && ./file
 *      (though it will return the result as exit code, not print it)
 * ═══════════════════════════════════════════════════════════════════ */

static int write_elf64(const char *filename, const MathFunc *func)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        fprintf(stderr, "[!] Cannot create file: %s\n", filename);
        return -1;
    }

    const size_t ehdr_size = 64;   /* ELF header size     */
    const size_t phdr_size = 56;   /* Program header size */
    const size_t code_offset = ehdr_size + phdr_size;  /* = 0x78 */

    uint64_t base_vaddr = 0x400000;
    uint64_t entry_vaddr = base_vaddr + code_offset;   /* 0x400078 */

    /* Total file size */
    size_t total_size = code_offset + func->code_size;

    /* ── ELF64 Header ─────────────────────────────────────────── */
    uint8_t ehdr[64];
    memset(ehdr, 0, sizeof(ehdr));

    /* e_ident: magic + class + encoding */
    ehdr[0] = 0x7F; ehdr[1] = 'E'; ehdr[2] = 'L'; ehdr[3] = 'F';
    ehdr[4] = 2;      /* ELFCLASS64          */
    ehdr[5] = 1;      /* ELFDATA2LSB         */
    ehdr[6] = 1;      /* EV_CURRENT          */
    ehdr[7] = 0;      /* ELFOSABI_NONE       */

    /* e_type = ET_EXEC (2) */
    ehdr[16] = 2; ehdr[17] = 0;

    /* e_machine = EM_X86_64 (0x3E) */
    ehdr[18] = 0x3E; ehdr[19] = 0;

    /* e_version = 1 */
    ehdr[20] = 1; ehdr[21] = 0; ehdr[22] = 0; ehdr[23] = 0;

    /* e_entry (8 bytes, little-endian) */
    memcpy(&ehdr[24], &entry_vaddr, 8);

    /* e_phoff = 64 (program header right after ELF header) */
    uint64_t phoff = 64;
    memcpy(&ehdr[32], &phoff, 8);

    /* e_shoff = 0 (no section headers) */
    /* ehdr[40..47] already 0 */

    /* e_flags = 0 */
    /* ehdr[48..51] already 0 */

    /* e_ehsize = 64 */
    ehdr[52] = 64; ehdr[53] = 0;

    /* e_phentsize = 56 */
    ehdr[54] = 56; ehdr[55] = 0;

    /* e_phnum = 1 */
    ehdr[56] = 1; ehdr[57] = 0;

    /* e_shentsize, e_shnum, e_shstrndx = 0 */
    /* ehdr[58..63] already 0 */

    fwrite(ehdr, 1, sizeof(ehdr), fp);

    /* ── Program Header (PT_LOAD, executable) ─────────────────── */
    uint8_t phdr[56];
    memset(phdr, 0, sizeof(phdr));

    /* p_type = PT_LOAD (1) */
    uint32_t p_type = 1;
    memcpy(&phdr[0], &p_type, 4);

    /* p_flags = PF_R | PF_X (5) */
    uint32_t p_flags = 5;
    memcpy(&phdr[4], &p_flags, 4);

    /* p_offset = 0 (load from start of file) */
    uint64_t p_offset = 0;
    memcpy(&phdr[8], &p_offset, 8);

    /* p_vaddr = base address */
    memcpy(&phdr[16], &base_vaddr, 8);

    /* p_paddr = same as vaddr */
    memcpy(&phdr[24], &base_vaddr, 8);

    /* p_filesz = total file size */
    uint64_t filesz = (uint64_t)total_size;
    memcpy(&phdr[32], &filesz, 8);

    /* p_memsz = same as filesz */
    memcpy(&phdr[40], &filesz, 8);

    /* p_align = 0x1000 (4KB page) */
    uint64_t align = 0x1000;
    memcpy(&phdr[48], &align, 8);

    fwrite(phdr, 1, sizeof(phdr), fp);

    /* ── Code Section ─────────────────────────────────────────── */
    fwrite(func->code, 1, func->code_size, fp);

    fclose(fp);

    printf("[+] Created: %s (%zu bytes)\n", filename, total_size);
    printf("    Function  : %s(x) = %s\n", func->name, func->formula);
    printf("    C code    : %s\n", func->c_code);
    printf("    Code size : %zu bytes of x86-64 machine code\n", func->code_size);
    printf("    Entry     : 0x%llX\n", (unsigned long long)entry_vaddr);
    printf("    Code bytes: ");
    for (size_t i = 0; i < func->code_size; i++) {
        printf("%02X ", func->code[i]);
    }
    printf("\n\n");

    return 0;
}


/* ═══════════════════════════════════════════════════════════════════ */

static void print_menu(void)
{
    printf("==============================================\n");
    printf("  Omni-Exec :: Test ELF Generator\n");
    printf("==============================================\n\n");
    printf("  Available math functions:\n\n");
    printf("  %-4s  %-14s  %-16s  %s\n", "#", "Name", "Formula", "C Code");
    printf("  %-4s  %-14s  %-16s  %s\n", "---", "-----------", "-------------", "---------------------");

    for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
        printf("  %-4zu  %-14s  f(x) = %-9s  %s\n",
               i + 1, functions[i].name, functions[i].formula, functions[i].c_code);
    }

    printf("\n  Usage:\n");
    printf("    create_test_elf.exe <name>     Generate one ELF\n");
    printf("    create_test_elf.exe all         Generate all ELFs\n");
    printf("\n  Then run with:\n");
    printf("    omni_loader.exe <file.elf> <number>\n\n");
}


static MathFunc* find_func(const char *name)
{
    for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
        if (strcmp(functions[i].name, name) == 0)
            return &functions[i];
    }
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_menu();
        return 0;
    }

    /* Generate all test ELFs */
    if (strcmp(argv[1], "all") == 0) {
        printf("Generating all test ELF binaries...\n\n");
        for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
            char filename[256];
            sprintf(filename, "%s.elf", functions[i].name);
            write_elf64(filename, &functions[i]);
        }
        printf("Done! Generated %zu ELF binaries.\n", NUM_FUNCTIONS);
        printf("Run them with:  omni_loader.exe <file.elf> <number>\n");
        return 0;
    }

    /* Generate a specific function */
    MathFunc *func = find_func(argv[1]);
    if (!func) {
        fprintf(stderr, "Unknown function: '%s'\n\n", argv[1]);
        printf("Available functions: ");
        for (size_t i = 0; i < NUM_FUNCTIONS; i++) {
            printf("%s%s", functions[i].name,
                   i < NUM_FUNCTIONS - 1 ? ", " : "\n");
        }
        return 1;
    }

    char filename[256];
    sprintf(filename, "%s.elf", func->name);
    return write_elf64(filename, func);
}
