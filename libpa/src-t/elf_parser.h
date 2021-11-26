//
// Created by joshua on 19.10.18.
//

#ifndef ENCLAVE_ELF_PARSER_H
#define ENCLAVE_ELF_PARSER_H

#include "pa_error.h"
#include <stdint.h>

#ifndef IDENT_SIZE
#define IDENT_SIZE 16
#endif

#ifndef PREFIX_TEXT
#define PREFIX_TEXT ".text."
#endif

#ifndef PREFIX_RELA
#define PREFIX_RELA ".rela"
#endif

#ifndef PREFIX_DATA
#define PREFIX_DATA ".data.rel.local."
#endif

/*#ifndef SYMBOL_TABLE_NAME
#define SYMBOL_TABLE_NAME ".symtab"
#endif*/

#ifndef PREFIX_RODATA
#define PREFIX_RODATA ".rodata"
#endif

#define ELF_R_SYM(info) ((info) >> 32)
#define ELF_R_TYPE(info) ((Elf_Word)(info))
#define ELF_R_INFO(sym, type) (((sym) << 32) + (Elf_Word)(type))


#define ELF_S_BIND(info) ((info) >> 4)
#define ELF_S_TYPE(info) ((info) & 0b00001111)
#define ELF_S_INFO(bind, type) (((bind) << 4) + ((type) & 0b00001111))

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
	R_X86_64_64 = 1,
	R_X86_64_PC32 = 2,
	R_X86_64_PLT32 = 4,
	R_X86_64_GOTPCREL = 9,
	R_X86_64_REX_GOTP = 42
} elf_relocation_types;

typedef enum
{
	symbol_type_notype = 0,
	symbol_type_obj = 1,
	symbol_type_fct = 2,
	symbol_type_section = 3,
	symbol_type_file = 4,
	symbol_type_enclave = 10,
} elf_symbol_types;

typedef enum
{
	symbol_binding_local = 0,
	symbol_binding_global = 1,
	symbol_binding_weak = 2,
} elf_symbol_bindings;

typedef enum
{
	section_index_undefined = 0,
	section_index_abs = 0xFFF1,
	section_index_common = 0xFFF2
} elf_special_section_indexes;

typedef enum
{
	section_type_progbits = 1,
	section_type_symtab = 2,
	section_type_nobits = 8
} elf_section_type;

typedef uint64_t Elf_Addr;
typedef uint16_t Elf_Half;
typedef uint64_t Elf_Off;
typedef int32_t Elf_Sword;
typedef uint32_t Elf_Word;
typedef uint64_t Elf_DWord;
typedef int64_t Elf_SDword;

typedef struct
{
	unsigned char ident[IDENT_SIZE];
	Elf_Half type;
	Elf_Half machine;
	Elf_Word version;
	Elf_Addr entry;
	Elf_Off pHeaderOffset;
	Elf_Off section_header_offset;
	Elf_Word flags;
	Elf_Half headerSize;
	Elf_Half pHeaderSize;
	Elf_Half pHeaderNum;
	Elf_Half sHeaderSize;
	Elf_Half sectionHeaderCount;
	Elf_Half section_header_string_table_index;
} elf_header_t;

typedef struct
{
	Elf_Word name_offset;
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
	Elf_Addr offset;
	Elf_DWord info;
	Elf_SDword addend;
} elf_relocation_t;

typedef struct
{
	Elf_Word name_offset; //< Name index in string table
	unsigned char info;
	unsigned char other;
	Elf_Half sHeaderIndex;
	Elf_Addr value;
	Elf_DWord size;
} elf_symbol_t;

typedef struct elf_section_symtab_t
{
	void *symtab_section_header, *symtab_section, *symtab_string_section;
	uint32_t symtab_string_section_length;
} elf_section_symtab_t;

dl_status_t elf_check_header(void *file);

void elf_get_section_data(void *destination, Elf_DWord data_size, Elf_Off offset, void *file);

#endif //ENCLAVE_ELF_PARSER_H
