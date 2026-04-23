/*
 * Omni-Exec — Step 1: Dual-Format Binary Parser
 * -----------------------------------------------
 * Detects whether an x86-64 binary is a Windows PE or Linux ELF,
 * then parses just enough headers to locate the entry point address
 * and the executable code section/segment.
 *
 * Build:
 *   Windows:  cl omni_parser.c /Fe:omni_parser.exe
 *         or  gcc omni_parser.c -o omni_parser.exe
 *   Linux:    gcc omni_parser.c -o omni_parser
 *
 * Usage:  ./omni_parser <path-to-binary>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* ─── Magic constants ─────────────────────────────────────────────── */
#define MZ_MAGIC        0x5A4D          /* 'MZ' — DOS/PE signature       */
#define PE_SIGNATURE    0x00004550      /* 'PE\0\0'                      */
#define ELF_MAGIC       "\x7F""ELF"    /* ELF magic bytes               */
#define ELFCLASS64      2              /* 64-bit ELF                    */
#define PT_LOAD         1              /* Loadable ELF segment          */
#define PF_X            0x1            /* Executable segment flag       */

/* ─── Minimal PE structures (only fields we need) ─────────────────── */

/* DOS Header — we only care about e_magic and e_lfanew */
typedef struct {
    uint16_t e_magic;       /* Must be MZ_MAGIC (0x5A4D)              */
    uint8_t  _pad[58];      /* Skip irrelevant DOS fields             */
    uint32_t e_lfanew;      /* File offset to the PE (NT) header      */
} DOS_Header;

/* COFF File Header (sits right after the PE signature) */
typedef struct {
    uint16_t Machine;               /* 0x8664 for x86-64              */
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_Header;

/* Optional Header — PE32+ (64-bit), trimmed to what we need */
typedef struct {
    uint16_t Magic;                 /* 0x020B for PE32+               */
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;   /* ← RVA of entry point           */
    uint32_t BaseOfCode;
    uint64_t ImageBase;             /* Preferred load address          */
} PE_OptionalHeader64;

/* Section Header — we scan for ".text" */
typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;        /* RVA of section in memory       */
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;      /* File offset of section data    */
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} PE_SectionHeader;

/* ─── Minimal ELF64 structures ────────────────────────────────────── */

typedef struct {
    uint8_t  e_ident[16];   /* Magic, class, endianness, etc.         */
    uint16_t e_type;        /* Object file type                       */
    uint16_t e_machine;     /* Architecture (0x3E = x86-64)           */
    uint32_t e_version;
    uint64_t e_entry;       /* ← Virtual address of entry point       */
    uint64_t e_phoff;       /* Program header table file offset       */
    uint64_t e_shoff;       /* Section header table file offset       */
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;   /* Size of one program header entry       */
    uint16_t e_phnum;       /* Number of program header entries       */
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;        /* Segment type (PT_LOAD, etc.)           */
    uint32_t p_flags;       /* Segment flags (R/W/X)                  */
    uint64_t p_offset;      /* File offset of segment                 */
    uint64_t p_vaddr;       /* Virtual address in memory              */
    uint64_t p_paddr;       /* Physical address (usually = p_vaddr)   */
    uint64_t p_filesz;      /* Size of segment in file                */
    uint64_t p_memsz;       /* Size of segment in memory              */
    uint64_t p_align;       /* Alignment                              */
} Elf64_Phdr;

/* ─── Parser functions ────────────────────────────────────────────── */

/*
 * parse_pe — Parse a PE (Portable Executable) binary.
 * Locates AddressOfEntryPoint and the .text section.
 */
static int parse_pe(FILE *fp) {
    DOS_Header dos;
    rewind(fp);

    if (fread(&dos, sizeof(dos), 1, fp) != 1) {
        fprintf(stderr, "[!] Failed to read DOS header.\n");
        return -1;
    }

    /* Jump to the PE signature at offset e_lfanew */
    if (fseek(fp, dos.e_lfanew, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Invalid e_lfanew offset (0x%X).\n", dos.e_lfanew);
        return -1;
    }

    uint32_t pe_sig;
    if (fread(&pe_sig, sizeof(pe_sig), 1, fp) != 1 || pe_sig != PE_SIGNATURE) {
        fprintf(stderr, "[!] PE signature not found (got 0x%08X).\n", pe_sig);
        return -1;
    }

    /* Read COFF header */
    COFF_Header coff;
    if (fread(&coff, sizeof(coff), 1, fp) != 1) {
        fprintf(stderr, "[!] Failed to read COFF header.\n");
        return -1;
    }

    if (coff.Machine != 0x8664) {
        fprintf(stderr, "[!] Not an x86-64 PE (Machine = 0x%04X).\n", coff.Machine);
        return -1;
    }

    /* Read the Optional Header (PE32+) */
    PE_OptionalHeader64 opt;
    if (fread(&opt, sizeof(opt), 1, fp) != 1) {
        fprintf(stderr, "[!] Failed to read Optional header.\n");
        return -1;
    }

    if (opt.Magic != 0x020B) {
        fprintf(stderr, "[!] Not a PE32+ optional header (Magic = 0x%04X).\n", opt.Magic);
        return -1;
    }

    /* Skip the rest of the optional header to reach section headers */
    long section_table_offset = dos.e_lfanew                /* PE sig offset   */
                              + 4                            /* PE signature     */
                              + sizeof(COFF_Header)          /* COFF header      */
                              + coff.SizeOfOptionalHeader;   /* Full opt header  */

    if (fseek(fp, section_table_offset, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Failed to seek to section table.\n");
        return -1;
    }

    /* ── Print results ─────────────────────────────────────────────── */
    printf("==============================================\n");
    printf("  Omni-Exec :: Dual-Format Binary Parser\n");
    printf("==============================================\n\n");
    printf("  Detected Format    : Windows PE (PE32+, x86-64)\n");
    printf("  Image Base         : 0x%016llX\n", (unsigned long long)opt.ImageBase);
    printf("  Entry Point (RVA)  : 0x%08X\n", opt.AddressOfEntryPoint);
    printf("  Entry Point (VA)   : 0x%016llX\n",
           (unsigned long long)(opt.ImageBase + opt.AddressOfEntryPoint));
    printf("  Number of Sections : %u\n\n", coff.NumberOfSections);

    /* Scan section headers for .text */
    int found_text = 0;
    for (uint16_t i = 0; i < coff.NumberOfSections; i++) {
        PE_SectionHeader sec;
        if (fread(&sec, sizeof(sec), 1, fp) != 1) {
            fprintf(stderr, "[!] Failed to read section header #%u.\n", i);
            return -1;
        }

        /* Check if this is the .text section */
        if (strncmp(sec.Name, ".text", 5) == 0) {
            found_text = 1;
            printf("  .text Section Found:\n");
            printf("    Virtual Address  : 0x%08X\n", sec.VirtualAddress);
            printf("    Virtual Size     : 0x%08X (%u bytes)\n",
                   sec.VirtualSize, sec.VirtualSize);
            printf("    Raw Data Offset  : 0x%08X\n", sec.PointerToRawData);
            printf("    Raw Data Size    : 0x%08X (%u bytes)\n",
                   sec.SizeOfRawData, sec.SizeOfRawData);
        }
    }

    if (!found_text) {
        printf("  [!] .text section not found in this PE.\n");
    }

    printf("\n==============================================\n");
    return 0;
}

/*
 * parse_elf — Parse an ELF64 binary.
 * Locates the entry point and the first executable PT_LOAD segment.
 */
static int parse_elf(FILE *fp) {
    Elf64_Ehdr ehdr;
    rewind(fp);

    if (fread(&ehdr, sizeof(ehdr), 1, fp) != 1) {
        fprintf(stderr, "[!] Failed to read ELF header.\n");
        return -1;
    }

    /* Verify 64-bit ELF */
    if (ehdr.e_ident[4] != ELFCLASS64) {
        fprintf(stderr, "[!] Not a 64-bit ELF (class = %u).\n", ehdr.e_ident[4]);
        return -1;
    }

    /* Verify x86-64 architecture */
    if (ehdr.e_machine != 0x3E) {
        fprintf(stderr, "[!] Not an x86-64 ELF (machine = 0x%04X).\n", ehdr.e_machine);
        return -1;
    }

    /* ── Print results ─────────────────────────────────────────────── */
    printf("==============================================\n");
    printf("  Omni-Exec :: Dual-Format Binary Parser\n");
    printf("==============================================\n\n");
    printf("  Detected Format      : Linux ELF (ELF64, x86-64)\n");
    printf("  Entry Point (VA)     : 0x%016llX\n", (unsigned long long)ehdr.e_entry);
    printf("  Program Header Off   : 0x%llX\n", (unsigned long long)ehdr.e_phoff);
    printf("  Num Program Headers  : %u\n\n", ehdr.e_phnum);

    /* Seek to program header table */
    if (fseek(fp, (long)ehdr.e_phoff, SEEK_SET) != 0) {
        fprintf(stderr, "[!] Failed to seek to program headers.\n");
        return -1;
    }

    /* Scan for executable PT_LOAD segments */
    int found_exec = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (fread(&phdr, sizeof(phdr), 1, fp) != 1) {
            fprintf(stderr, "[!] Failed to read program header #%u.\n", i);
            return -1;
        }

        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            found_exec = 1;
            printf("  Executable Segment (PT_LOAD) Found:\n");
            printf("    Virtual Address  : 0x%016llX\n", (unsigned long long)phdr.p_vaddr);
            printf("    File Offset      : 0x%016llX\n", (unsigned long long)phdr.p_offset);
            printf("    File Size        : 0x%llX (%llu bytes)\n",
                   (unsigned long long)phdr.p_filesz,
                   (unsigned long long)phdr.p_filesz);
            printf("    Memory Size      : 0x%llX (%llu bytes)\n",
                   (unsigned long long)phdr.p_memsz,
                   (unsigned long long)phdr.p_memsz);
            printf("    Alignment        : 0x%llX\n", (unsigned long long)phdr.p_align);
            break;  /* First executable segment is typically .text */
        }
    }

    if (!found_exec) {
        printf("  [!] No executable PT_LOAD segment found.\n");
    }

    printf("\n==============================================\n");
    return 0;
}

/* ─── Main: detect format and dispatch ────────────────────────────── */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <path-to-binary>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    /* Read the first 4 bytes to identify the format */
    uint8_t magic[4];
    if (fread(magic, 1, 4, fp) != 4) {
        fprintf(stderr, "[!] File too small to identify.\n");
        fclose(fp);
        return 1;
    }

    int result;

    if (magic[0] == 'M' && magic[1] == 'Z') {
        /* ── Windows PE ── */
        result = parse_pe(fp);

    } else if (memcmp(magic, ELF_MAGIC, 4) == 0) {
        /* ── Linux ELF ── */
        result = parse_elf(fp);

    } else {
        fprintf(stderr, "[!] Unknown binary format.\n");
        fprintf(stderr, "    Magic bytes: %02X %02X %02X %02X\n",
                magic[0], magic[1], magic[2], magic[3]);
        fclose(fp);
        return 1;
    }

    fclose(fp);
    return (result == 0) ? 0 : 1;
}
