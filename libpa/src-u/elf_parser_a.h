#ifndef PA_LIBRARY_ELF_PARSER_A_H
#define PA_LIBRARY_ELF_PARSER_A_H

#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "pa_error.h"

#ifndef NULL
#define NULL 0
#endif

#ifndef IDENT_SIZE
#define IDENT_SIZE 16
#endif

#ifndef PREFIX_TEXT
#define PREFIX_TEXT ".text"
#endif

typedef uint64_t Elf_Addr;
typedef uint16_t Elf_Half;
typedef uint64_t Elf_Off;
typedef int32_t Elf_Sword;
typedef uint32_t Elf_Word;
typedef uint64_t Elf_DWord;
typedef int64_t Elf_SDword;

typedef enum
{
	magic_0 = 0x7f,
	magic_1 = 0x45,
	magic_2 = 0x4c,
	magic_3 = 0x46,
	elf_x86 = 0x01,
	elf_x86_64 = 0x02,
	elf_lsb = 0x01
} elf_magic;

typedef enum
{
	section_type_progbits = 1,
	section_type_symtab = 2,
	section_type_nobits = 8
} elf_section_type;

typedef struct
{
	unsigned char ident[IDENT_SIZE];
	Elf_Half type;
	Elf_Half machine;
	Elf_Word version;
	Elf_Addr entry;
	Elf_Off pHeaderOffset;
	Elf_Off sectionHeaderOffset;
	Elf_Word flags;
	Elf_Half headerSize;
	Elf_Half pHeaderSize;
	Elf_Half pHeaderNum;
	Elf_Half sHeaderSize;
	Elf_Half sectionHeaderCount;
	Elf_Half stringTableIndex;
} elf_header_t;

typedef struct
{
	Elf_Word name;
	Elf_Word type;
	Elf_DWord flags;
	Elf_Addr addr;
	Elf_Off offset;
	Elf_DWord size;
	Elf_Word link;
	Elf_Word info;
	Elf_DWord addralign;
	Elf_DWord entsize;
} elf_section_header_t;

typedef struct
{
	Elf_Word name_offset;
	unsigned char info;
	unsigned char other;
	Elf_Half sHeaderIndex;
	Elf_Addr value;
	Elf_DWord size;
} elf_symbol_t;

typedef struct
{
	void *symtab_section_header, *symtab_section, *symtab_string_section;
	uint32_t symtab_string_section_length;
} elf_section_symtab_t;

dl_status_t _pa_get_symtab(elf_section_symtab_t *sections, char *enclave_path);

dl_status_t _pa_unmap_enclave(void);

static dl_status_t elf_check_header(elf_header_t *header_ptr);

#endif //PA_LIBRARY_ELF_PARSER_A_H
