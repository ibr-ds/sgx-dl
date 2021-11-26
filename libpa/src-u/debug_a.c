//
// Created by joshua on 15.10.18.
//

#include "pa.h"

#include "__debug.h"

#ifdef DEBUG

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>

#ifndef PA_MAX_FCT_NAME_LENGTH
#define PA_MAX_FCT_NAME_LENGTH 64
#endif

#ifndef PA_MAX_OBJ_NAME_LENGTH
#define PA_MAX_OBJ_NAME_LENGTH 64
#endif

typedef enum
{
	_pa_fct_not_loaded = 0b0,
	_pa_fct_loaded = 0b1,
	_pa_fct_is_loading = 0b10
} _fct_status_t;

#ifndef IDENT_SIZE
#define IDENT_SIZE 16
#endif

#ifndef PREFIX_TEXT
#define PREFIX_TEXT ".text."
#endif

#ifndef PREFIX_REL
#define PREFIX_REL ".rel."
#endif

#define ELF_R_SYM(info) ((info) >> 32)
#define ELF_R_TYPE(info) ((Elf_Word)(info))

#define ELF_S_BIND(info) ((info) >> 4)
#define ELF_S_TYPE(info) ((info) & 00001111)

typedef enum
{
	symbol_type_obj = 1,
	symtol_type_fct = 2
} elf_symbol_types;

typedef enum
{
	symbol_binding_global = 1
} elf_symbol_bindings;

typedef uint64_t Elf_Addr;
typedef uint16_t Elf_Half;
typedef uint64_t Elf_Off;
typedef int32_t Elf_Sword;
typedef uint32_t Elf_Word;
typedef uint64_t Elf_DWord;
typedef int64_t Elf_SDWord;

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
	Elf_Addr offset;
	Elf_DWord info;
	Elf_SDWord addend;
} elf_relocation_t;

typedef struct
{
	Elf_Word name;
	unsigned char info;
	unsigned char other;
	Elf_Half sHeaderIndex;
	Elf_Addr value;
	Elf_DWord size;
} elf_symbol_t;

typedef struct
{
	Elf_Word type;
	Elf_Word flags;
	Elf_Off offset;
	Elf_Addr v_addr;
	Elf_Addr p_addr;
	Elf_DWord f_size;
	Elf_DWord m_size;
	Elf_DWord align;
} elf_program_header_t;

typedef struct
{
	Elf_SDWord tag;
	union
	{
		Elf_DWord val;
		Elf_Addr ptr;
	} _union;
} elf_dynamic_type_t;

typedef struct obj_table
{
	struct obj_table *pred;
	struct obj_table *succ;
	char name[PA_MAX_OBJ_NAME_LENGTH];
	void *addr;
} _pa_obj_table_t;

typedef struct file_table
{
	struct file_table *pred;
	struct file_table *succ;
	unsigned int id;
	elf_header_t *file_header;
	elf_section_header_t *section_header;
	elf_section_header_t *symbol_table;
	_pa_obj_table_t *_obj_table;
} _pa_file_table_t;

typedef struct fct_table _pa_fct_table_t;

typedef struct lru_table
{
	struct lru_table *pred, *succ;
	_pa_fct_table_t *fct;
} _pa_fct_lru_table_t;

typedef struct rel_table
{
	struct rel_table *succ;
	elf_relocation_t *rel;
} _pa_fct_rel_table_t;

typedef struct caller_table
{
	struct caller_table *succ;
	_pa_fct_table_t *fct;
	_pa_fct_rel_table_t *rel;
} _pa_fct_caller_table_t;

typedef struct subcall_table
{
	struct subcall_table *succ;
	_pa_fct_table_t *fct;
} _pa_fct_subcall_table_t;

typedef struct fct_table
{
	struct fct_table *pred;
	struct fct_table *succ;
	unsigned int id, text_section, rela_section;
	_fct_status_t status;
	char fct_name[PA_MAX_FCT_NAME_LENGTH];
	_pa_file_table_t *file_table_entry;
	_pa_fct_caller_table_t *caller_table;
	_pa_fct_subcall_table_t *subcall_table;
	void *addr;
	unsigned int calls_in_progress;
	_pa_fct_lru_table_t *lru_entry;
} _pa_fct_table_t;

typedef enum
{
	memory_not_in_use = 0,
	memory_in_use = 1
} _mem_status_t;

typedef struct mem_ctl
{
	struct mem_ctl *pred, *succ;
	size_t size;
	_mem_status_t status;
} _pa_mem_ctl_t;

typedef struct
{
	void *addr;
	char *fct_name;
} _pa_enclave_fct_table_t;

void debug_print_int(int *ptr)
{
	printf("[Debug] Value: %d.\n", *ptr);
}

void debug_print_double(double *ptr)
{
	printf("[Debug] Value: %f.\n", *ptr);
}

void debug_print_long_int(long int *ptr)
{
	printf("[Debug] Value: %ld.\n", *ptr);
}

__attribute__((weak)) void debug_print(char *string)
{
	printf("[Debug] %s.\n", string);
}

__attribute__((weak)) void debug_print_error(int *ptr)
{
	printf("[Debug] Error: 0x%#010x.\n", *ptr);
}

__attribute__((weak)) void debug_print_pointer(void *ptr)
{
	printf("[Debug] PTR: %p.\n", ptr);
}

void debug_print_fct_table_t(void *ptr)
{
	_pa_fct_table_t *localptr = ptr;
	printf("(%p) ID: %d, ADDR: %p, PRED: %p , SUCC: %p STATUS: %#010x FCT_NAME: %s FILE_TABLE_ENTRY: %p TEXT: %u RELA: %u\n SUBCALL_TABLE: %p CALLER_TABLE: %p CALL_COUNT: %u LRU: %p\n",
	       localptr, localptr->id, localptr->addr, localptr->pred, localptr->succ, localptr->status, localptr->fct_name, localptr->file_table_entry, localptr->text_section, localptr->rela_section, localptr->subcall_table,
	       localptr->caller_table, localptr->calls_in_progress, localptr->lru_entry);
}

void debug_print_elf_header(void *ptr)
{
	elf_header_t *header = ptr;
	printf("ELF Header: \n");
	printf(" Ident: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x (%s) \n Type: %#04x\n Machine: %#010x\n "
	       "Version: %u\n Entry: 0x%#016lx\n pHeaderOffset: %ld (Byte)\n section_header_offset: %ld (Byte)\n"
	       " Flags: 0x%#08x\n HeaderSize: %hu (Byte)\n pHeaderSize: %hu\n pHeaderNum: %hu\n sHeaderSize: %hu\n sectionHeaderCount: %hu\n section_header_string_table_index: %hu\n", header->ident[0], header->ident[1], header->ident[2], header->ident[3], header->ident[4], header->ident[5], header->ident[6], header->ident[7],
	       header->ident[8], header->ident[9], header->ident[10], header->ident[11], header->ident[12], header->ident[13], header->ident[14], header->ident[15],
	       header->ident, header->type, header->machine, header->version, header->entry, header->pHeaderOffset, header->section_header_offset,
	       header->flags, header->headerSize, header->pHeaderSize, header->pHeaderNum, header->sHeaderSize, header->sectionHeaderCount, header->section_header_string_table_index);
}

void debug_print_elf_section_header(void *ptr, char *stringTable, int id)
{
	elf_section_header_t *header = ptr;
	printf("[%d]ELF Section Header: \n", id);
	printf(" Sectionname: %s\n Offset: %lu\n Size: %lu\n EntSize: %lu\n Link: %u\n Info: %u\n", (stringTable + header->name), header->offset, header->size, header->entsize, header->link, header->info);
}

void debug_print_elf_relocation(void *ptr)
{
	elf_relocation_t *localptr = (elf_relocation_t *) ptr;
	printf("Relocation: \n");
	printf(" Offset: %lu Info: %lu \n Addend: %ld.\n Symbol: %lu.\n Type: %d.\n", localptr->offset, localptr->info, localptr->addend, ELF_R_SYM(localptr->info), ELF_R_TYPE(localptr->info));
}

void debug_print_elf_symbol(void *ptr, char *stringTable)
{
	elf_symbol_t *localptr = (elf_symbol_t *) ptr;
	printf("Symbol: \n");
	printf(" Name: %s\n Value: %lu\n Size: %lu\n Info: %#02x\n Other: %#02x\n SectionHeaderIndex: %hu\n Binding: %#01x\n Type: %#01x\n",
	       stringTable, localptr->value, localptr->size, localptr->info, localptr->other, localptr->sHeaderIndex, ELF_S_BIND(localptr->info), ELF_S_TYPE(localptr->info));
}

void debug_print_file_table_t(void *ptr)
{
	_pa_file_table_t *localptr = (_pa_file_table_t *) ptr;
	printf("File Table: \n");
	printf("(%p) ID: %d\n PRED: %p\n SUCC: %p\n FILE_HEADER: %p\n SECTION_HEADER: %p\n SYMBOL_HEADER: %p\n",
	       localptr, localptr->id, localptr->pred, localptr->succ, localptr->file_header, localptr->section_header, localptr->symbol_table);
}

void debug_print_obj_table_t(void *ptr)
{
	_pa_obj_table_t *localptr = ptr;
	printf("Object Table: \n");
	printf("(%p) NAME: %s\n ADDR: %p\n PRED: %p\n SUCC: %p\n", localptr, localptr->name, localptr->addr, localptr->pred, localptr->succ);
}

void debug_print_mem_ctl_t(void *ptr)
{
	_pa_mem_ctl_t *localptr = ptr;
	printf("ADDR: %p PRED: %p SUCC: %p SIZE: %lu Bytes STATUS: %d\n", localptr, localptr->pred, localptr->succ, localptr->size, localptr->status);
}

void debug_print_subcall_table_t(void *ptr)
{
	_pa_fct_subcall_table_t *localptr = (_pa_fct_subcall_table_t *) ptr;
	printf("(%p) FCT_NAME: %s FCT_ADDR: %p FCT_STATUS: %#010x SUCC: %p\n", localptr, localptr->fct->fct_name, localptr->fct, localptr->fct->status, localptr->succ);
}

void debug_print_caller_table_t(void *ptr)
{
	_pa_fct_caller_table_t *localptr = (_pa_fct_caller_table_t *) ptr;
	printf("(%p) FCT_NAME: %s REL_PTR: %p SUCC: %p\n", localptr, localptr->fct->fct_name, localptr->rel, localptr->succ);
}

void debug_print_rel_table_t(void *ptr)
{
	_pa_fct_rel_table_t *localptr = (_pa_fct_rel_table_t *) ptr;
	printf("(%p) REL_ADDR: %p SUCC: %p\n", localptr, localptr->rel, localptr->succ);
}

void debug_print_lru_table_t(void *ptr)
{
	_pa_fct_lru_table_t *localptr = (_pa_fct_lru_table_t *) ptr;
	printf("LRU (%p): PRED: %p SUCC: %p FCT: %s (%p)\n", localptr, localptr->pred, localptr->succ, localptr->fct->fct_name, localptr->fct);
}

void debug_print_enclave_fct_table_t(void *ptr)
{
	_pa_enclave_fct_table_t *localptr = (_pa_enclave_fct_table_t *) ptr;
	printf("(%p)Enclave_Fct:\n Name: %s\n Addr: %p\n", localptr, localptr->fct_name, localptr->addr);
}

#endif
