#ifndef SGX_DL_PA_DEBUG_H
#define SGX_DL_PA_DEBUG_H

//#define DEBUG
//#define DEBUG_PA_ADD_FCT_EX_SECTION_HEADER
//#define DEBUG_PA_LOAD_FCT_EX_GLOBAL_SYMBOL
//#define DEBUG_PA_LOAD_FCT_EX_LOCAL_SYMBOL

#ifdef DEBUG
#define _DEBUG

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

#endif //SGX_DL_PA_DEBUG_H
