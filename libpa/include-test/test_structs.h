#ifndef ENCLAVE_KEYVALUESTORE_H
#define ENCLAVE_KEYVALUESTORE_H

typedef struct __mystruct
{
	int a;
	int b;
	double c;
} myStruct_t;

typedef struct __test_cases
{
	int int_section_common;
	int int_section_bss;
	int int_section_data;
	int static_int_section_bss;
	int static_int_section_data;
	int const_int_section_common;
	int const_int_section_rodata;
	int static_const_int_section_bss;
	int static_const_int_section_rodata;
	int vol_int_section_common;
	int vol_int_section_bss;
	int vol_int_section_data;
	int static_vol_int_section_bss;
	int static_vol_int_section_data;
	int fct_test_register_a;
	int fct_test_register_b;
	int fct_test_register_c;
	int static_fct_test_a;
	int static_fct_test_b;
	int static_fct_test_c;
	int static_fct_test_value;
	double double_section_common;
	double double_section_bss;
	double double_section_data;
	double static_double_section_bss;
	double static_double_section_data;
	double const_double_section_common;
	double const_double_section_rodata;
	double static_const_double_section_bss;
	double static_const_double_section_rodata;
	double vol_double_section_common;
	double vol_double_section_bss;
	double vol_double_section_data;
	double static_vol_double_section_bss;
	double static_vol_double_section_data;
	char char_array_section_data[32];
	char static_char_array_section_data[32];
	char const_char_array_section_rodata[32];
	char static_const_char_array_section_rodata[32];
	char vol_char_array_section_data[32];
	char static_vol_char_array_section_data[32];
	void *int_section_common_ptr;
	void *int_section_bss_ptr;
	void *int_section_data_ptr;
	void *double_section_common_ptr;
	void *double_section_bss_ptr;
	void *double_section_data_ptr;
	void *char_array_section_data_ptr;
	void *static_int_section_bss_ptr;
	void *static_int_section_data_ptr;
	void *static_double_section_bss_ptr;
	void *static_double_section_data_ptr;
	void *static_char_array_section_data_ptr;
	void *const_int_section_common_ptr;
	void *const_int_section_rodata_ptr;
	void *const_double_section_common_ptr;
	void *const_double_section_rodata_ptr;
	void *const_char_array_section_rodata_ptr;
	void *static_const_int_section_bss_ptr;
	void *static_const_int_section_rodata_ptr;
	void *static_const_double_section_bss_ptr;
	void *static_const_double_section_rodata_ptr;
	void *static_const_char_array_section_rodata_ptr;
	void *vol_int_section_common_ptr;
	void *vol_int_section_bss_ptr;
	void *vol_int_section_data_ptr;
	void *vol_double_section_common_ptr;
	void *vol_double_section_bss_ptr;
	void *vol_double_section_data_ptr;
	void *vol_char_array_section_data_ptr;
	void *static_vol_int_section_bss_ptr;
	void *static_vol_int_section_data_ptr;
	void *static_vol_double_section_bss_ptr;
	void *static_vol_double_section_data_ptr;
	void *static_vol_char_array_section_data_ptr;
	void *static_fct_test_value_ptr;
} test_cases_t;

typedef struct __test_struct
{
	int intern;
	int _extern;
	int extern_with_functions;
	int global;
	double double_value;
	char secret_message_1[10];
	char secret_message_2[10];
	char secret_message_3[10];
	char secret_message_4[10];
	test_cases_t test_case;
} test_struct_t;

typedef struct __test_header_args
{
	int test_header_int;
	int test_header_secret_calculation;
	int test_header_int_fct;
	char test_header_string[32];
} test_header_args_t;

typedef struct __test_pa_call_ex_args
{
	void *_int;
	void *_double;
	void *_char;
	void *_long;
	void *_short;
	void *_float;
	void *_void_ptr;
} test_pa_call_ex_args_t;

typedef struct __test_fct_recursion
{
	int fct_recursion_value_global;
	int fct_recursion_value_local;
	int fct_recursion_hop_value_global;
	int fct_recursion_hop_value_local;
} test_fct_recursion_t;

typedef struct __test_fct_reload
{
	int *fct_reload_result_1;
	int *fct_reload_result_2;
	int *fct_reload_result_3;
	int *fct_reload_result_4;
	int *fct_reload_result_5;
} test_fct_reload_t;

typedef struct __test_fct_reload_set_value
{
	int index;
	int value;
} test_fct_reload_set_value_t;

typedef struct __test_fct_blocked
{
	int *fct_blocked_sn;
	int *fct_blocked_sl;
	int *fct_blocked_sn_x;
	int *fct_blocked_sl_x;
	int *fct_blocked_sn_X;
	int *fct_blocked_sl_X;
	int *fct_blocked_snsn;
	int *fct_blocked_snsl;
	int *fct_blocked_snxsn;
	int *fct_blocked_snxsl;
	int *fct_blocked_slxsn;
	int *fct_blocked_slxsl;
	int *fct_blocked_snsn_x;
	int *fct_blocked_snsl_x;
	int *fct_blocked_snxsn_x;
	int *fct_blocked_snxsl_x;
	int *fct_blocked_slxsn_x;
	int *fct_blocked_slxsl_x;
	int *fct_blocked_snsn_X;
	int *fct_blocked_snsl_X;
	int *fct_blocked_snxsn_X;
	int *fct_blocked_snxsl_X;
	int *fct_blocked_slxsn_X;
	int *fct_blocked_slxsl_X;
	int *fct_blocked_init;
	int *fct_blocked_init_x;
	int *fct_blocked_init_X;
} test_fct_blocked_t;

typedef struct __test_fct_sgx_call
{
	int *fct_sgx_call_value_0;
	int *fct_sgx_call_value_1;
	void *fct_sgx_call_value_0_addr;
	void *fct_sgx_call_value_1_addr;
} test_fct_sgx_call_t;

#endif //ENCLAVE_KEYVALUESTORE_H
