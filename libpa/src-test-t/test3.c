#include "test_structs.h"
int value_c = 101;
int secret_storage;
int local_section_bss = 0;
int local_section_data = -1;
//int const_int_section_rodata = 1;
//int const_int_section_common;
//char const_char_array_section_rodata = 'a';
int static_const_int_rodata = -1;
char static_const_char_array[] = {"Hey"};
myStruct_t myStruct_bss;
//volatile int vol_int_section_common;
//volatile int vol_int_section_bss;
//(volatile)int vol_int_section_data = 5;
//int static_vol_int_section_bss;
//int static_vol_int_section_data = 5;
//double static_vol_double_section_data = 1.11;
