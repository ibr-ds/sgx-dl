#ifndef ENCLAVE_PA_HEADER_H
#define ENCLAVE_PA_HEADER_H

#include "pa_error.h"
#include "elf_parser.h"
#include <sgx.h>
#include <stdlib.h>

#ifdef DEBUG
extern void debug_print_int(int* ptr);
extern void debug_print_long_int(long int* ptr);
extern void debug_print_double(double* ptr);
extern void debug_print(char* string);
extern void debug_print_pointer(void* ptr);
extern void debug_print_fct_table_t(void* ptr);
extern void debug_print_error(int* ptr);
extern void debug_print_elf_header(void* ptr);
extern void debug_print_elf_section_header(void* ptr, char* stringTable,int id);

extern void debug_print_elf_relocation(void* ptr);
extern void debug_print_elf_symbol(void* ptr, char* stringTable);
extern void debug_print_file_table_t(void* ptr);
extern void debug_print_obj_table_t(void* ptr);
extern void debug_print_mem_ctl_t(void* ptr);
extern void debug_print_subcall_table_t( void* ptr);
extern void debug_print_caller_table_t(void* ptr);
extern void debug_print_rel_table_t(void* ptr);
extern void debug_print_lru_table_t( void* ptr);
extern void debug_print_enclave_fct_table_t(void* ptr);
#endif

sgx_status_t ocall_malloc(void** retval, size_t size);
sgx_status_t ocall_free(void* addr);
sgx_status_t _pa_get_symtab(dl_status_t* retval, struct elf_section_symtab_t* sections, char* enclave_path);
sgx_status_t _pa_unmap_enclave(dl_status_t* retval);

// TODO: sgx_rsrv is not exposed in the SDK yet, so we have to redefine the symbols here
void * sgx_alloc_rsrv_mem(size_t length);
int sgx_free_rsrv_mem(void * addr, size_t length);
sgx_status_t sgx_tprotect_rsrv_mem(void *addr, size_t len, int prot);
size_t get_rsrv_size(void);
void * get_rsrv_base(void);
size_t get_rsrv_end(void);
#define SGX_PROT_READ	0x1		/* page can be read */
#define SGX_PROT_WRITE	0x2		/* page can be written */
#define SGX_PROT_EXEC	0x4		/* page can be executed */
#define SGX_PROT_NONE	0x0		/* page can not be accessed */

#endif //ENCLAVE_PA_HEADER_H
