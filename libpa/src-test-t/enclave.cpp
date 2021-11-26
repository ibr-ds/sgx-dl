#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "pa.h"
#include "enclave_t.h"
#include "test_structs.h"

extern uint8_t __ImageBase;

extern "C" void printf(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

static void debug_print_error(dl_status_t status)
{
	printf("Error: 0x%x\n", status);
}

extern "C" void pa_print_error(const char *fmt, ...)
{
	char buf[BUFSIZ] = {'\0'};
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void *enclave_read_file(char *file_name)
{
	int file_size;
	void *fileptr;
	void *obj_file_ptr;
	read_file(&fileptr, file_name, &file_size);
	if (fileptr == NULL)
	{
		return NULL;
	}
	obj_file_ptr = (void *) malloc(file_size * sizeof(char));
	memcpy(obj_file_ptr, fileptr, file_size);
	free_file(fileptr);
	return obj_file_ptr;
}

static uint64_t __assertion_counter;

#define assert_equal(actual, expected) do { uint64_t line = __LINE__;\
	const char *file = __FILE__;\
	if ((actual) != (expected)) {\
		printf("!!!Assertion failed in %s:%lu: %s != %s\nActual: %lu (0x%x)\n", file, line, #actual, #expected, (uint64_t)actual, (uint64_t)actual);\
		abort();\
	}\
	__assertion_counter++;\
} while(0);

#define assert_equal_string(actual, expected) do { uint64_t line = __LINE__;\
	const char *file = __FILE__;\
	if (actual == NULL || strcmp(actual, expected) != 0) {\
		printf("!!!Assertion failed in %s:%lu: %s != %s\nActual: %s\n", file, line, #actual, #expected, actual);\
		abort();\
	}\
	__assertion_counter++;\
} while(0);

#define assertion_summary() do {\
	printf("%lu Assertions passed\n", __assertion_counter);\
} while(0);

//////////////////////////////////////////
void *thread_file_o = NULL;

dl_file_handle_t thread_file_o_fh = DL_EMPTY_HANDLE;

void thread_init(void)
{
	thread_file_o = enclave_read_file((char *)"thread_test.o");
	if (thread_file_o == NULL)
	{
		return;
	}
	dl_status_t status = dl_add_file(thread_file_o, &thread_file_o_fh);
	assert_equal(status, DL_SUCCESS);
}

void thread_test(void)
{
	void *ret_val = 0;
	dl_status_t status = dl_add_fct((char *) "thread_test", thread_file_o_fh);
	if (status != DL_SUCCESS && status != PA_INVALID_FILE_ID && status != PA_FUNCTION_ALREADY_EXISTS)
	{
		//if(status != DL_SUCCESS)
		debug_print_error(status);
	}
	status = dl_load_fct((char *) "thread_test");
	if (status != DL_SUCCESS && status != PA_FUNCTION_ALREADY_LOADED)
	{
		//if(status != DL_SUCCESS)
		debug_print_error(status);
	}
	status = dl_call_ex((char *) "thread_test", &ret_val, NULL);
	if (status != DL_SUCCESS)
	{
		debug_print_error(status);
	}
	printf("%p\n", ret_val);
	assert(ret_val == (void *) 0x007);
	return;
}
//////////////////////////////////////////
#define RUNS 50000

void measurement(void)
{
	void *file_test_measurement = enclave_read_file((char *)"test_measurement.o");
	dl_file_handle_t file_test_measurement_fh = DL_EMPTY_HANDLE;
	dl_status_t status = dl_add_file(file_test_measurement, &file_test_measurement_fh);
	assert_equal(status, DL_SUCCESS);
	//ADD .O FILE
	for (int i = 0; i < RUNS; i++)
	{
		status = dl_add_fct((char *) "testfct", file_test_measurement_fh);
		if (status != DL_SUCCESS)
		{
			debug_print_error(status);
			return;
		}
		status = dl_load_fct((char *) "testfct");
		if (status != DL_SUCCESS)
		{
			debug_print_error(status);
			return;
		}
		measurement_start_timer();
		status = dl_call_ex((char *) "testfct", NULL, NULL);
		measurement_stop_timer();
		if (status != DL_SUCCESS && status != PA_FUNCTION_ALREADY_LOADED)
		{
			debug_print_error(status);
			return;
		}
		dl_destroy();
	}
}

//////////////////////////////////////////

void *file_test_o;
void *file_test_2_o;
void *file_test_3_o;
void *file_test_cases_o;
void *file_test_cases_var_o;
void *file_test_header_app_o;
void *file_test_header_fct_o;
void *file_test_cases_abort_o;
void *file_test_datarel_o;

dl_file_handle_t file_test_2_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_3_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_cases_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_cases_var_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_datarel_o_fh = DL_EMPTY_HANDLE;

static void test_1()
{
	printf("Test 1: ");
	test_struct_t args;
	memset(&args, 0, sizeof(test_struct_t));

	dl_status_t status = dl_add_file(file_test_2_o, &file_test_2_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_file(file_test_o, &file_test_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "_init", file_test_2_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fill_struct", file_test_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "get_int_a", file_test_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "get_int_b", file_test_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "get_secret_message", file_test_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "_a", file_test_2_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "insert_string", file_test_2_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_load_fct((char *) "_a");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_file(file_test_3_o, &file_test_3_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_file(file_test_cases_o, &file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "_init_test", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "_copy_string", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "global_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "static_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "const_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "static_const_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "volatile_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "static_volatile_variables", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_test_register", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_file(file_test_cases_var_o, &file_test_cases_var_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "static_fct_test_get_value", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call((char *) "_init", (void *) &args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(args.intern, 3);
	assert_equal(args._extern, 101);
	assert_equal(args.extern_with_functions, 1337);
	assert_equal(args.global, 2018);
	assert_equal(args.double_value, 1.883300);
	assert_equal_string(args.secret_message_1, "HalloWelt");
	assert_equal_string(args.secret_message_2, "TESTSTR");
	assert_equal_string(args.secret_message_3, "RDATATEST");
	assert_equal_string(args.secret_message_4, "TESTSTR");

	assert_equal_string(args.test_case.char_array_section_data, "Global_Variables");
	assert_equal(args.test_case.int_section_common, -1);
	assert_equal(args.test_case.int_section_bss, 0);
	assert_equal(args.test_case.int_section_data, 1);
	assert_equal(args.test_case.double_section_common, -1.0);
	assert_equal(args.test_case.double_section_bss, 0.0);
	assert_equal(args.test_case.double_section_data, 1.234567);

	assert_equal_string(args.test_case.static_char_array_section_data, "Static_Variables");
	assert_equal(args.test_case.static_int_section_bss, 0);
	assert_equal(args.test_case.static_int_section_data, 1);
	assert_equal(args.test_case.static_double_section_bss, 0.0);
	assert_equal(args.test_case.static_double_section_data, 1.234567);

	assert_equal_string(args.test_case.const_char_array_section_rodata, "Const_Variables");
	//assert_equal(args.test_case.const_int_section_common, 0); // Const common means uninitialized value that is const
	assert_equal(args.test_case.const_int_section_rodata, 1);
	//assert_equal(args.test_case.const_double_section_common, 0.0); // Const common means uninitialized value that is const
	assert_equal(args.test_case.const_double_section_rodata, 1.234567);

	assert_equal_string(args.test_case.static_const_char_array_section_rodata, "Static_Const_Variables");
	assert_equal(args.test_case.static_const_int_section_bss, 0);
	assert_equal(args.test_case.static_const_int_section_rodata, 1);
	assert_equal(args.test_case.static_const_double_section_bss, 0.0);
	assert_equal(args.test_case.static_const_double_section_rodata, 1.234567);

	assert_equal_string(args.test_case.vol_char_array_section_data, "Volatile_Variables");
	assert_equal(args.test_case.vol_int_section_common, -1);
	assert_equal(args.test_case.vol_int_section_bss, 0);
	assert_equal(args.test_case.vol_int_section_data, 1);
	assert_equal(args.test_case.vol_double_section_common, -1.0);
	assert_equal(args.test_case.vol_double_section_bss, 0.0);
	assert_equal(args.test_case.vol_double_section_data, 1.234567);

	assert_equal_string(args.test_case.static_vol_char_array_section_data, "Static_Volatile_Variables");
	assert_equal(args.test_case.static_vol_int_section_bss, 0);
	assert_equal(args.test_case.static_vol_int_section_data, 1);
	assert_equal(args.test_case.static_vol_double_section_bss, 0.0);
	assert_equal(args.test_case.static_vol_double_section_data, 1.234567);

	assert_equal(args.test_case.fct_test_register_a, 1);
	assert_equal(args.test_case.fct_test_register_b, 4);
	assert_equal(args.test_case.fct_test_register_c, 6);

	assert_equal(args.test_case.static_fct_test_a, 3);
	assert_equal(args.test_case.static_fct_test_b, 2);
	assert_equal(args.test_case.static_fct_test_c, 560);

	assert_equal(args.test_case.static_fct_test_value, 555);

	printf("SUCCESS\n");
}

dl_file_handle_t file_test_header_app_o_fh = DL_EMPTY_HANDLE;
dl_file_handle_t file_test_header_fct_o_fh = DL_EMPTY_HANDLE;

void test_2()
{
	printf("Test Header: ");
	test_header_args_t header_args;
	memset(&header_args, 0, sizeof(test_header_args_t));

	dl_status_t status = dl_add_file(file_test_header_app_o, &file_test_header_app_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "test_header_main", file_test_header_app_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_file(file_test_header_fct_o, &file_test_header_fct_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "test_header_secret_calculation", file_test_header_fct_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "test_header_get_string", file_test_header_fct_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call((char *) "test_header_main", &header_args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(header_args.test_header_int, 1337);
	assert_equal(header_args.test_header_int_fct, 999);
	assert_equal(header_args.test_header_secret_calculation, 10);
	assert_equal_string(header_args.test_header_string, "Test_Header");

	printf("SUCCESS\n");
}

void test_pa_call_ex()
{
	printf("Test dl_call_ex: ");

	test_pa_call_ex_args_t call_args;
	memset(&call_args, 0, sizeof(test_pa_call_ex_args_t));
	char pa_call_ex_char = 'A';
	short pa_call_ex_short = 1;
	int pa_call_ex_int = 1;
	long int pa_call_ex_lint = 1;
	float pa_call_ex_float = 1.5;
	double pa_call_ex_double = 1.5;
	void *pa_call_ex_void_ptr = (void *) 0x2;

	//Testcases PA_CALL_EX
	dl_status_t status = dl_add_fct((char *) "pa_call_ex_int_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_int_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_int_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_int_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_int_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_int_nr_a", NULL, &pa_call_ex_int);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_int_r_na", (void **) &call_args._int, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_int_r_a", (void **) &call_args._int, &call_args._int);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_lint_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_lint_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_lint_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_lint_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_lint_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_lint_nr_a", NULL, &pa_call_ex_lint);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_lint_r_na", (void **) &call_args._long, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_lint_r_a", (void **) &call_args._long, &call_args._long);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_char_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_char_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_char_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_char_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_char_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_char_nr_a", NULL, &pa_call_ex_char);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_char_r_na", (void **) &call_args._char, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_char_r_a", (void **) &call_args._char, &call_args._char);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_short_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_short_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_short_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_short_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_short_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_short_nr_a", NULL, &pa_call_ex_short);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_short_r_na", (void **) &call_args._short, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_short_r_a", (void **) &call_args._short, &call_args._short);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_ptr_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_ptr_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_ptr_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_ptr_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_ptr_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_ptr_nr_a", NULL, &pa_call_ex_void_ptr);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_ptr_r_na", (void **) &call_args._void_ptr, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_ptr_r_a", (void **) &call_args._void_ptr, &call_args._void_ptr);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_float_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_float_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_float_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_float_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_float_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_float_nr_a", NULL, &pa_call_ex_float);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_float_r_na", (void **) &call_args._float, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_float_r_a", (void **) &call_args._float, &call_args._float);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_double_nr_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_double_nr_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_double_r_na", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "pa_call_ex_double_r_a", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_double_nr_na", NULL, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_double_nr_a", NULL, &pa_call_ex_double);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_double_r_na", (void **) &call_args._double, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "pa_call_ex_double_r_a", (void **) &call_args._double, &call_args._double);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	char _char = *(char *)&call_args._char;
	assert_equal(_char, 'B');
	short _short = *(short *)&call_args._short;
	assert_equal(_short, 2000);
	int _int = *(int *)&call_args._int;
	assert_equal(_int, 2000);
	long _long = *(long *)&call_args._long;
	assert_equal(_long, 2000);
	float _float = *(float *)&call_args._float;
	assert_equal(_float, 1999.8f);
	double _double = *(double *)&call_args._double;
	assert_equal(_double, 1999.8);
	assert_equal(call_args._void_ptr, (void*)0x1337);

	printf("SUCCESS\n");
}

void test_recursion()
{
	printf("Test recursion: ");

	test_fct_recursion_t recursion_args;
	memset(&recursion_args, 0, sizeof(test_fct_recursion_t));

	//Fct Recursion
	dl_status_t status = dl_add_fct((char *) "fct_recursion_init", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_recursion_global", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_recursion_warmup_global", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_recursion_hop_global", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_recursion_reset", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_recursion_init", NULL, &recursion_args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(recursion_args.fct_recursion_value_global, 25);
	assert_equal(recursion_args.fct_recursion_value_local, 50);
	assert_equal(recursion_args.fct_recursion_hop_value_global, 100);
	assert_equal(recursion_args.fct_recursion_hop_value_local, 75);

	printf("SUCCESS\n");
}

void test_reload()
{
	printf("Test reload: ");

	test_fct_reload_t reload_args;
	test_fct_reload_set_value_t set_value_args;
	memset(&reload_args, 0, sizeof(test_fct_reload_t));
	memset(&set_value_args, 0, sizeof(test_fct_reload_set_value_t));

	dl_status_t status = dl_add_fct((char *) "fct_reload_calculation", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_get_value", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_set_value", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_calculation", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_layer_4", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_layer_3", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_layer_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_layer_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_layer_0", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_reset", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_warmup", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_value_3_block_memory", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_calculation", (void **) &reload_args.fct_reload_result_1, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_get_value");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	set_value_args.index = 1;
	set_value_args.value = 10;
	status = dl_call_ex((char *) "fct_reload_set_value", NULL, (void *) &set_value_args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	set_value_args.index = 2;
	status = dl_call_ex((char *) "fct_reload_set_value", NULL, (void *) &set_value_args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_calculation", (void **) &reload_args.fct_reload_result_2, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//Cleanup
	status = dl_unload_fct((char *) "fct_reload_set_value");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_get_value");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_calculation", (void **) &reload_args.fct_reload_result_2, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//UNLOAD TEST WITH SUBCALLS
	status = dl_call_ex((char *) "fct_reload_value_3_calculation", (void **) &reload_args.fct_reload_result_3, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_0");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call((char *) "fct_reload_value_3_block_memory", NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_value_3_calculation", (void **) &reload_args.fct_reload_result_4, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//Cleanup
	status = dl_unload_fct((char *) "fct_reload_value_3_block_memory");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_0");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_reload_value_3_layer_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_value_3_calculation", (void **) &reload_args.fct_reload_result_4, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//Symbol not found test
	status = dl_add_fct((char *) "fct_reload_missed_symbol_init", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_missed_symbol_fct_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_missed_symbol_get_value_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_missed_symbol_get_value_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_missed_symbol_get_value_3", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_reload_missed_symbol_get_missed_symbol", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_missed_symbol_init", (void **) &reload_args.fct_reload_result_5, NULL);
	assert_equal(status, PA_UNRESOLVED_RELOCATION);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	dl_file_handle_t file_test_cases_abort_o_fh = DL_EMPTY_HANDLE;
	status = dl_add_file(file_test_cases_abort_o, &file_test_cases_abort_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	reload_args.fct_reload_result_5 = 0;
	status = dl_call_ex((char *) "fct_reload_missed_symbol_init", (void **) &reload_args.fct_reload_result_5, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(*(int *)&reload_args.fct_reload_result_5, 2137);

	reload_args.fct_reload_result_5 = 0;
	status = dl_unload_fct((char *) "fct_reload_missed_symbol_get_value_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//temp_1 = malloc(6);

	status = dl_call_ex((char *) "fct_reload_missed_symbol_init", (void **) &reload_args.fct_reload_result_5, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);
	//Cleanup
	//free(temp_1);

	status = dl_unload_fct((char *) "fct_reload_missed_symbol_get_value_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_reload_missed_symbol_init", (void **) &reload_args.fct_reload_result_5, NULL);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(*(int *)&reload_args.fct_reload_result_1, 113);
	assert_equal(*(int *)&reload_args.fct_reload_result_2, 123);
	assert_equal(*(int *)&reload_args.fct_reload_result_3, 4011);
	assert_equal(*(int *)&reload_args.fct_reload_result_4, 4011);
	assert_equal(*(int *)&reload_args.fct_reload_result_5, 2137);

	printf("SUCCESS\n");
}

void test_blocked()
{
	printf("Test blocked: ");

	void *temp_int = 0;
	test_fct_blocked_t blocked_args;
	memset(&blocked_args, 0, sizeof(test_fct_blocked_t));

	dl_status_t status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sn, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);


	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sl, (void **) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sn_x, (void **) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sl_x, (void **) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sn_X, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &blocked_args.fct_blocked_sl_X, (void **) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsn, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsl, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsn, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsl, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsn, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsl, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	///////////////////////////////////////////
	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsn_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsl_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct("fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsn_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsl_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_sn", (void **) &temp_int, (void *) 1337);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(*(int *)&temp_int, 1338);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsn_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsl_x, (void *) 999);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsn_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snsl_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_sn_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_del_fct((char *) "fct_blocked_snsn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_snsn", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", &temp_int, (void *) 1337);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(*(int *)&temp_int, 1339);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsn_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_snxsl_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_sn_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsn_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_snsn", (void **) &blocked_args.fct_blocked_slxsl_X, (void *) 1000);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_init", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3_2_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3_2_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_3_3", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4_2_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4_2_2", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_blocked_fct_4_3", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_load_fct((char *) "fct_blocked_fct_3_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_fct_4", NULL, (void *) 1);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_init", (void **) &blocked_args.fct_blocked_init, (void *) 1);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_init");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_2_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_init", (void **) &blocked_args.fct_blocked_init_x, (void *) 1);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_2_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_3_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_2_1");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_unload_fct((char *) "fct_blocked_fct_4_3");
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_blocked_init", (void **) &blocked_args.fct_blocked_init_X, (void *) 1);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	assert_equal(*(int *)&blocked_args.fct_blocked_sn, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_sl, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_sn_x, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_sl_x, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_sn_X, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_sl_X, 1000);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsn, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsl, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsn, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsl, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsn, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsl, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsn_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsl_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsn_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsl_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsn_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsl_x, 1001);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsn_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_snsl_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsn_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_snxsl_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsn_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_slxsl_X, 1002);
	assert_equal(*(int *)&blocked_args.fct_blocked_init, 32);
	assert_equal(*(int *)&blocked_args.fct_blocked_init_x, 32);
	assert_equal(*(int *)&blocked_args.fct_blocked_init_X, 32);

	printf("SUCCESS\n");
}

void test_sgxcalls()
{
	printf("Test SGX calls: ");
	test_fct_sgx_call_t sgx_call_args;
	memset(&sgx_call_args, 0, sizeof(test_fct_sgx_call_t));


	dl_status_t status = dl_add_fct((char *) "fct_sgx_call_init", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct((char *) "fct_sgx_call_get_value_1", file_test_cases_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_call_ex((char *) "fct_sgx_call_init", NULL, (void *) &sgx_call_args);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	//Print fct table
	/*
	dl_file_handle_t file_test_2_o_fh = DL_EMPTY_HANDLE;
	status = dl_add_file(file_test_2_o, &file_test_2_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);
	//*/

	assert_equal(*(int *)&sgx_call_args.fct_sgx_call_value_0, 999);
	assert_equal(*(int *)&sgx_call_args.fct_sgx_call_value_1, 1000);

	printf("SUCCESS\n");
}

void test_datarela()
{
	printf("Data relocation tests: ");

	dl_status_t status = dl_add_file(file_test_datarel_o, &file_test_datarel_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	status = dl_add_fct("fct_datarel_access_first", file_test_datarel_o_fh);
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	char *res = NULL;
	status = dl_call_ex((char *)"fct_datarel_access_first", (void**)&res, NULL);
	assert_equal_string(res, "first");

	printf("SUCCESS\n");
}

//Dev
void init(void)
{
	file_test_o = enclave_read_file((char *)"test.c.o");
	file_test_2_o = enclave_read_file((char *)"test2.c.o");
	file_test_3_o = enclave_read_file((char *)"test3.c.o");
	file_test_cases_o = enclave_read_file((char *)"test_cases.c.o");
	file_test_cases_var_o = enclave_read_file((char *)"test_cases_var.c.o");
	file_test_header_app_o = enclave_read_file((char *)"test_header_app.c.o");
	file_test_header_fct_o = enclave_read_file((char *)"test_header_fct.c.o");
	file_test_cases_abort_o = enclave_read_file((char *)"test_cases_abort.c.o");
	file_test_datarel_o = enclave_read_file((char *)"test_datarel.c.o");

	char run_2 = 0x00;
	dl_status_t status;
	//Testcases General/PA_LOAD_FCT

#ifdef SIMMODE
	sgx_sha256_hash_t symhash = {0x27, 0xca, 0xb5, 0xd6, 0x93, 0x4a, 0x0b, 0xd4, 0x4c, 0x29, 0x8d, 0x6d, 0x1e, 0x74, 0x70, 0xac, 0xd1, 0x68, 0xf7, 0x4c, 0xe0, 0x9c, 0x76, 0xca, 0x9e, 0xe2, 0x0a, 0x85, 0x89, 0xa8, 0x0f, 0x17};
	sgx_sha256_hash_t strhash = {0x54, 0xaf, 0xdf, 0x69, 0xa8, 0x4b, 0x7a, 0x3d, 0x06, 0xab, 0xa5, 0x3a, 0x57, 0x6d, 0xce, 0x53, 0xb3, 0xcf, 0x9e, 0x87, 0x89, 0xb1, 0xaa, 0x28, 0xa9, 0x44, 0x7f, 0xd3, 0x05, 0x8d, 0xdd, 0xe4};
	status = dl_add_enclave_fct("libpatestenclavesim.signed.so", &symhash, &strhash);
#else
	sgx_sha256_hash_t symhash = {0x6c, 0x30, 0x1d, 0x52, 0x23, 0x6a, 0x7e, 0xb9, 0x5f, 0x0a, 0x40, 0x3f, 0x2b, 0x01, 0x0a, 0x77, 0xf8, 0x26, 0x9a, 0x14, 0xed, 0xd2, 0x46, 0x2d, 0x37, 0x74, 0x4d, 0xc1, 0xe9, 0xc1, 0x89, 0x3b};
	sgx_sha256_hash_t strhash = {0xce, 0x50, 0xe8, 0x57, 0xa6, 0xdf, 0xe5, 0xd8, 0x79, 0xc7, 0x0a, 0x66, 0xef, 0x69, 0x31, 0xda, 0xd6, 0x2c, 0x5e, 0xa2, 0xe3, 0x7e, 0xf4, 0x12, 0x36, 0x32, 0xbf, 0xa8, 0x7e, 0x15, 0x5e, 0x7c};
	status = dl_add_enclave_fct((char *) "libpatestenclave.signed.so", &symhash, &strhash);
#endif
	assert_equal(status, DL_SUCCESS);

	printf("\nSTARTING RUN 1\n\n");

	test_1();

	test_2();

	test_pa_call_ex();

	test_recursion();

	//FCT UNLOAD TEST
	/*memset(&args,0,sizeof(test_struct_t));
	status = dl_unload_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = dl_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}*/
	//FCT DEL TEST
	/*memset(&args,0,sizeof(test_struct_t));
	status = dl_del_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_add_fct(1,"_init",2,file_test_2_o);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = dl_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}*/
	//FCT RELOAD TESTS

	test_reload();

	test_blocked();

	test_sgxcalls();

	test_datarela();

	status = dl_destroy();
	assert_equal(status, DL_SUCCESS);
	assert_equal(dl_check_consistency(), DL_SUCCESS);

	file_test_o_fh = DL_EMPTY_HANDLE;
	file_test_2_o_fh = DL_EMPTY_HANDLE;
	file_test_3_o_fh = DL_EMPTY_HANDLE;
	file_test_cases_o_fh = DL_EMPTY_HANDLE;
	file_test_cases_var_o_fh = DL_EMPTY_HANDLE;
	file_test_header_app_o_fh = DL_EMPTY_HANDLE;
	file_test_header_fct_o_fh = DL_EMPTY_HANDLE;
	file_test_datarel_o_fh = DL_EMPTY_HANDLE;

	printf("\nSTARTING RUN 2\n\n");

	RUN_2:
#ifdef SIMMODE
	status = dl_add_enclave_fct("libpatestenclavesim.signed.so", &symhash, &strhash);
#else
	status = dl_add_enclave_fct("libpatestenclave.signed.so", &symhash, &strhash);
#endif
	assert_equal(status, DL_SUCCESS);

	test_1();

	test_2();

	test_pa_call_ex();

	test_recursion();

	//FCT UNLOAD TEST
	/*memset(&args,0,sizeof(test_struct_t));
	status = dl_unload_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = dl_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}*/
	//FCT DEL TEST
	/*memset(&args,0,sizeof(test_struct_t));
	status = dl_del_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_add_fct(1,"_init",2,file_test_2_o);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = dl_load_fct(1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = pa_call(1,(void*)&args);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}*/

	test_reload();

	test_blocked();

	test_sgxcalls();

	test_datarela();

	printf("\n");
	assertion_summary();
	printf("\nEND\n");

	//MALLOC TEST
	/*void* ptr_1,*ptr_2,*ptr_3,*ptr_4,*ptr_5;
	status = _pa_malloc(&ptr_1,2000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_1);
	memset(ptr_1,1,2000);
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_2);
	memset(ptr_2,2,1000);
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_3);
	memset(ptr_3,3,500);
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_4);
	memset(ptr_4,4,435);
	status = _pa_malloc(&ptr_5,1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_5);
	memset(ptr_5,5,1);
	//FREE TEST LEFT
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,2000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,3033);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,3032);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,2000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,3033);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,3032);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_1,2000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	//FREE TEST RIGHT
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,469);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,468);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,469);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,468);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_5,1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}*/
	//FREE TEST MIDDLE LEFT
	/*
	 *    status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_2);
	memset(ptr_2,2,1000);
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_3);
	memset(ptr_3,3,500);
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_4);
	memset(ptr_4,4,435);
	 */
	/*status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,1533);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,1532);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,1533);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,1532);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	//FREE TEST MIDDLE RIGHT
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,968);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,967);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,968);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,967);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	/////////////////////////////////////////
	status = _pa_free(ptr_2);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_5);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_4);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	status = _pa_free(ptr_3);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	/////////////////////////////////////////
	status = _pa_malloc(&ptr_1,2000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_1);
	memset(ptr_1,1,2000);
	status = _pa_malloc(&ptr_2,1000);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_2);
	memset(ptr_2,2,1000);
	status = _pa_malloc(&ptr_3,500);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_3);
	memset(ptr_3,3,500);
	status = _pa_malloc(&ptr_4,435);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_4);
	memset(ptr_4,4,435);
	status = _pa_malloc(&ptr_5,1);
	if(status != DL_SUCCESS){
		debug_print_error((int*)&status);
	}
	debug_print_pointer(ptr_5);
	memset(ptr_5,5,1);*/
}
