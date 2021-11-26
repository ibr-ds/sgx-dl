#include "test_structs.h"

#include <string.h>
#include <stdlib.h>

//Global variables
int int_section_common;
int int_section_bss = 0;
int int_section_data = 1;
double double_section_common;
double double_section_bss = 0;
double double_section_data = 1.234567;
char char_array_section_data[] = {"Global_Variables"};
//Static Variables
static int static_int_section_bss;
static int static_int_section_data = 1;
static double static_double_section_bss;
static double static_double_section_data = 1.234567;
static char static_char_array_section_data[] = {"Static_Variables"};
//Const Variables
const int const_int_section_common;
const int const_int_section_rodata = 1;
const double const_double_section_common;
const double const_double_section_rodata = 1.234567;
const char const_char_array_section_rodata[] = {"Const_Variables"};
//Static Const Variables
static const int static_const_int_section_bss;
static const int static_const_int_section_rodata = 1;
static const double static_const_double_section_bss;
static const double static_const_double_section_rodata = 1.234567;
static const char static_const_char_array_section_rodata[] = {"Static_Const_Variables"};
//Volatile Variables
volatile int vol_int_section_common;
volatile int vol_int_section_bss = 0;
volatile int vol_int_section_data = 1;
volatile double vol_double_section_common;
volatile double vol_double_section_bss = 0;
volatile double vol_double_section_data = 1.234567;
volatile char vol_char_array_section_data[] = {"Volatile_Variables"};
//Static volatile Variables
static volatile int static_vol_int_section_bss;
static volatile int static_vol_int_section_data = 1;
static volatile double static_vol_double_section_bss;
static volatile double static_vol_double_section_data = 1.234567;
static volatile char static_vol_char_array_section_data[] = {"Static_Volatile_Variables"};
//Static Function
static const int static_fct_test_value = 555;

extern int _a(void);

static int static_fct_test_int()
{
	return _a(); //RETURN 3
}

int static_fct_test_get_value()
{
	int temp = static_fct_test_int();
	temp = static_fct_test_value;
	return temp;
}

static int static_fct_test(test_cases_t *ptr)
{
	ptr->static_fct_test_a = static_fct_test_int();
	ptr->static_fct_test_b = (int_section_data + static_int_section_data);
	ptr->static_fct_test_value = static_fct_test_get_value();
	ptr->static_fct_test_value_ptr = (void *)&static_fct_test_value;
	return (static_fct_test_value + ptr->static_fct_test_a + ptr->static_fct_test_b);//560
}

//Register Variables
int fct_test_register(register int a, register int b)
{
	register int test = int_section_data;
	return a + b + test;
}

void _copy_string(char *destination, char *source)
{
	int count = 0;
	while (source[count] != '\0')
	{
		destination[count] = source[count];
		count++;
	}
	destination[count] = '\0';
}

void static_volatile_variables(test_cases_t *ptr)
{
	static_vol_int_section_bss++;
	static_vol_double_section_bss++;
	static_vol_int_section_bss--;
	static_vol_double_section_bss--;
	ptr->static_vol_int_section_bss = static_vol_int_section_bss;
	ptr->static_vol_int_section_data = static_vol_int_section_data;
	ptr->static_vol_double_section_bss = static_vol_double_section_bss;
	ptr->static_vol_double_section_data = static_vol_double_section_data;
	_copy_string((char *)&ptr->static_vol_char_array_section_data, (char *)static_vol_char_array_section_data);
	ptr->static_vol_int_section_bss_ptr = (void *)&static_vol_int_section_bss;
	ptr->static_vol_int_section_data_ptr = (void *)&static_vol_int_section_data;
	ptr->static_vol_double_section_bss_ptr = (void *)&static_vol_double_section_bss;
	ptr->static_vol_double_section_data_ptr = (void *)&static_vol_double_section_data;
	ptr->static_vol_char_array_section_data_ptr = (void *)&static_vol_char_array_section_data;
}

void volatile_variables(test_cases_t *ptr)
{
	vol_int_section_common = -1;
	vol_int_section_bss++;
	vol_double_section_bss++;
	vol_int_section_bss--;
	vol_double_section_bss--;
	ptr->vol_int_section_common = vol_int_section_common;
	ptr->vol_int_section_bss = vol_int_section_bss;
	ptr->vol_int_section_data = vol_int_section_data;
	vol_double_section_common = -1;
	ptr->vol_double_section_common = vol_double_section_common;
	ptr->vol_double_section_bss = vol_double_section_bss;
	ptr->vol_double_section_data = vol_double_section_data;
	_copy_string((char *)&ptr->vol_char_array_section_data, (char *)vol_char_array_section_data);
	ptr->vol_int_section_common_ptr = (void *)&vol_int_section_common;
	ptr->vol_int_section_bss_ptr = (void *)&vol_int_section_bss;
	ptr->vol_int_section_data_ptr = (void *)&vol_int_section_data;
	ptr->vol_double_section_common_ptr = (void *)&vol_double_section_common;
	ptr->vol_double_section_bss_ptr = (void *)&vol_double_section_bss;
	ptr->vol_double_section_data_ptr = (void *)&vol_double_section_data;
	ptr->vol_char_array_section_data_ptr = (void *)vol_char_array_section_data;
}

void static_const_variables(test_cases_t *ptr)
{
	ptr->static_const_int_section_bss = static_const_int_section_bss;
	ptr->static_const_int_section_rodata = static_const_int_section_rodata;
	ptr->static_const_double_section_bss = static_const_double_section_bss;
	ptr->static_const_double_section_rodata = static_const_double_section_rodata;
	_copy_string((char *)&ptr->static_const_char_array_section_rodata, (char *)static_const_char_array_section_rodata);
	ptr->static_const_int_section_bss_ptr = (void *)&static_const_int_section_bss;
	ptr->static_const_int_section_rodata_ptr = (void *)&static_const_int_section_rodata;
	ptr->static_const_double_section_bss_ptr = (void *)&static_const_double_section_bss;
	ptr->static_const_double_section_rodata_ptr = (void *)&static_const_double_section_rodata;
	ptr->static_const_char_array_section_rodata_ptr = (void *)static_const_char_array_section_rodata;
}

void const_variables(test_cases_t *ptr)
{
	//const_int_section_common = -1;
	ptr->const_int_section_common = const_int_section_common;
	ptr->const_int_section_rodata = const_int_section_rodata;
	//const_double_section_common = -1;
	ptr->const_double_section_common = const_double_section_common;
	ptr->const_double_section_rodata = const_double_section_rodata;
	_copy_string((char *)&ptr->const_char_array_section_rodata, (char *)const_char_array_section_rodata);
	ptr->const_int_section_common_ptr = (void *)&const_int_section_common;
	ptr->const_int_section_rodata_ptr = (void *)&const_int_section_rodata;
	ptr->const_double_section_common_ptr = (void *)&const_double_section_common;
	ptr->const_double_section_rodata_ptr = (void *)&const_double_section_rodata;
	ptr->const_char_array_section_rodata_ptr = (void *)const_char_array_section_rodata;
}

void static_variables(test_cases_t *ptr)
{
	static_int_section_bss++;
	static_double_section_bss++;
	static_int_section_bss--;
	static_double_section_bss--;
	ptr->static_int_section_bss = static_int_section_bss;
	ptr->static_int_section_data = static_int_section_data;
	ptr->static_double_section_bss = static_double_section_bss;
	ptr->static_double_section_data = static_double_section_data;
	_copy_string((char *)&ptr->static_char_array_section_data, static_char_array_section_data);
	ptr->static_int_section_bss_ptr = &static_int_section_bss;
	ptr->static_int_section_data_ptr = &static_int_section_data;
	ptr->static_double_section_bss_ptr = &static_double_section_bss;
	ptr->static_double_section_data_ptr = &static_double_section_data;
	ptr->static_char_array_section_data_ptr = static_char_array_section_data;
}

void global_variables(test_cases_t *ptr)
{
	int_section_common = -1;
	ptr->int_section_common = int_section_common;
	ptr->int_section_bss = int_section_bss;
	ptr->int_section_data = int_section_data;
	double_section_common = -1;
	ptr->double_section_common = double_section_common;
	ptr->double_section_bss = double_section_bss;
	ptr->double_section_data = double_section_data;
	_copy_string((char *)&ptr->char_array_section_data, char_array_section_data);
	ptr->int_section_common_ptr = &int_section_common;
	ptr->int_section_bss_ptr = &int_section_bss;
	ptr->int_section_data_ptr = &int_section_data;
	ptr->double_section_common_ptr = &double_section_common;
	ptr->double_section_bss_ptr = &double_section_bss;
	ptr->double_section_data_ptr = &double_section_data;
	ptr->char_array_section_data_ptr = char_array_section_data;
}

////////////PA_CALL_EX///////////////////////////////////////////////////////////////////////
static int pa_call_ex_int_variable;

void pa_call_ex_int_nr_na(void)
{
	pa_call_ex_int_variable = 999;
}

void pa_call_ex_int_nr_a(register int *val)
{
	pa_call_ex_int_variable += *val;
}

void *pa_call_ex_int_r_na(void)
{
	return (void *) (long)pa_call_ex_int_variable;
}

void *pa_call_ex_int_r_a(int *val)
{
	return (void *) (long)(pa_call_ex_int_variable + *val);
}

static long int pa_call_ex_lint_variable;

void pa_call_ex_lint_nr_na(void)
{
	pa_call_ex_lint_variable = 999;
}

void pa_call_ex_lint_nr_a(long int *val)
{
	pa_call_ex_lint_variable += *val;
}

void *pa_call_ex_lint_r_na(void)
{
	return (void *) pa_call_ex_lint_variable;
}

void *pa_call_ex_lint_r_a(long int *val)
{
	return (void *) (pa_call_ex_lint_variable += *val);
}

static char pa_call_ex_char_variable = ' ';

void pa_call_ex_char_nr_na(void)
{
	pa_call_ex_char_variable = 'Z';
}

void pa_call_ex_char_nr_a(char *ptr)
{
	pa_call_ex_char_variable = *ptr;
}

void *pa_call_ex_char_r_na(void)
{
	return (void *)(long)pa_call_ex_char_variable;
}

void *pa_call_ex_char_r_a(char *ptr)
{
	pa_call_ex_char_variable = (*ptr + 1);
	return (void*)(long)pa_call_ex_char_variable;
}

static short pa_call_ex_short_variable;

void pa_call_ex_short_nr_na(void)
{
	pa_call_ex_short_variable = 999;
}

void pa_call_ex_short_nr_a(short *val)
{
	pa_call_ex_short_variable += *val;
}

void *pa_call_ex_short_r_na(void)
{
	return (void *) (long)pa_call_ex_short_variable;
}

void *pa_call_ex_short_r_a(short *val)
{
	return (void *) (long)(pa_call_ex_short_variable + *val);
}

static void *pa_call_ex_ptr_variable;

void pa_call_ex_ptr_nr_na(void)
{
	pa_call_ex_ptr_variable = (void *) 0x999;
}

void pa_call_ex_ptr_nr_a(void *ptr)
{
	unsigned long int *localptr = ptr;
	pa_call_ex_ptr_variable += *localptr;
}

void *pa_call_ex_ptr_r_na(void)
{
	return pa_call_ex_ptr_variable;
}

void *pa_call_ex_ptr_r_a(void *ptr)
{
	unsigned long int *localptr = ptr;
	return (pa_call_ex_ptr_variable + *localptr + 1);
}

static float pa_call_ex_float_value;

void pa_call_ex_float_nr_na(void)
{
	pa_call_ex_float_value = 998.4;
}

void pa_call_ex_float_nr_a(float *ptr)
{
	pa_call_ex_float_value += *ptr;
}

void *pa_call_ex_float_r_na(void)
{
	int *ptr = (int *) &pa_call_ex_float_value;
	return (void *)(long)(int) *ptr;
	//return (void*) pa_call_ex_float_value;
}

void *pa_call_ex_float_r_a(float *ptr)
{
	pa_call_ex_float_value += *ptr;
	int *ret_ptr = (int *) &pa_call_ex_float_value;
	return (void *)(long)(int) *ret_ptr;
	//return (void*) (pa_call_ex_float_value += *ptr);
}

static double pa_call_ex_double_value;

void pa_call_ex_double_nr_na(void)
{
	pa_call_ex_double_value = 998.4;
}

void pa_call_ex_double_nr_a(double *ptr)
{
	pa_call_ex_double_value += *ptr;
}

void *pa_call_ex_double_r_na(void)
{
	void **ptr = (void **) &pa_call_ex_double_value;
	return *ptr;
	//return (void*) pa_call_ex_double_value;
}

void *pa_call_ex_double_r_a(double *ptr)
{
	pa_call_ex_double_value += *ptr;
	void **ret_ptr = (void **) &pa_call_ex_double_value;
	return *ret_ptr;
	//return (void*) (pa_call_ex_double_value + *ptr);
}

/////FCT_RECURSION//////////////////////////////////////////////////////////////////////////
int fct_recursion_hop_global(void);

static int fct_recursion_hop_local(void);

static int fct_recursion_value_global, fct_recursion_value_local, fct_recursion_hop_value_global,
		fct_recursion_hop_value_local;
char switch_global = 0x00, switch_local = 0x00;

int fct_recursion_global(void)
{
	fct_recursion_value_global++;
	if (fct_recursion_value_global == 25)
	{
		return fct_recursion_value_global;
	}
	return fct_recursion_global();
}

static int fct_recursion_local(void)
{
	fct_recursion_value_local++;
	if (fct_recursion_value_local == 50)
	{
		return fct_recursion_value_local;
	}
	return fct_recursion_local();
}

int fct_recursion_warmup_global(void)
{
	fct_recursion_hop_value_global = 0;
	switch_global = 0x01;
	return fct_recursion_hop_global();
}

int fct_recursion_hop_global(void)
{
	if (switch_global == 0x00)
	{
		return fct_recursion_warmup_global();
	}
	fct_recursion_hop_value_global++;
	if (fct_recursion_hop_value_global == 100)
	{
		return fct_recursion_hop_value_global;
	}
	return fct_recursion_hop_global();
}

static int fct_recursion_warmup_local(void)
{
	fct_recursion_hop_value_local = 0;
	switch_local = 0x01;
	return fct_recursion_hop_local();
}

static int fct_recursion_hop_local(void)
{
	if (switch_local == 0x00)
	{
		return fct_recursion_warmup_local();
	}
	fct_recursion_hop_value_local++;
	if (fct_recursion_hop_value_local == 75)
	{
		return fct_recursion_hop_value_local;
	}
	return fct_recursion_hop_local();
}

void fct_recursion_reset(void)
{
	switch_local = 0x0;
	switch_global = 0x0;
}

void *fct_recursion_init(void *args)
{
	test_fct_recursion_t *ptr = (test_fct_recursion_t*)args;
	fct_recursion_value_global = 0;
	ptr->fct_recursion_value_global = fct_recursion_global();
	fct_recursion_value_local = 0;
	ptr->fct_recursion_value_local = fct_recursion_local();
	ptr->fct_recursion_hop_value_global = fct_recursion_hop_global();
	ptr->fct_recursion_hop_value_local = fct_recursion_hop_local();
	fct_recursion_reset();
	return NULL;
}

/////FCT_RELOAD/////////////////////////////////////////////////////////////////////////////
int fct_reload_public_value = 5, fct_reload_value_3 = 1000;
static int fct_reload_privat_value = 5;
char switch_value_3 = 0x00;

int fct_reload_value_3_layer_1(void);

extern int missed_symbol;

void fct_reload_set_value(test_fct_reload_set_value_t *ptr)
{
	if (ptr->index == 1)
	{
		fct_reload_public_value = ptr->value;
	}
	else if (ptr->index == 2)
	{
		fct_reload_privat_value = ptr->value;
	}
	return;
}

int fct_reload_get_value(int index)
{
	if (index == 1)
	{
		return fct_reload_public_value;
	}
	else if (index == 2)
	{
		return fct_reload_privat_value;
	}
}

int fct_reload_calculation()
{
	test_fct_recursion_t recursion_args;
	int value1 = fct_reload_get_value(1);
	int value2 = fct_reload_get_value(2);
	fct_recursion_init(&recursion_args);
	return value1 + value2 + _a() + recursion_args.fct_recursion_hop_value_global;
}

void fct_reload_value_3_reset()
{
	fct_reload_value_3 = 1000;
}

int fct_reload_value_3_layer_0()
{
	return fct_reload_value_3;
}

int fct_reload_value_3_warmup()
{
	if (switch_value_3 == 0x00)
	{
		switch_value_3 = 0x01;
	}
	if (switch_value_3 == 0x02)
	{//Not reachable
		int a = fct_reload_value_3_layer_1();
		int b = fct_reload_value_3_layer_1();
		return (a + b) + fct_reload_value_3_layer_1();
	}
	return fct_reload_value_3_layer_1();
}

int fct_reload_value_3_layer_1()
{
	int value = fct_reload_value_3_layer_0();
	if (switch_value_3 == 0x00)
	{
		return fct_reload_value_3_warmup();
	}
	fct_reload_value_3++;
	if (value != 1005)
	{
		return fct_reload_value_3_layer_1();
	}
	return value;
}

int fct_reload_value_3_layer_2()
{
	int value_1 = fct_reload_value_3_layer_1();
	fct_reload_value_3_reset();
	int value_0 = fct_reload_value_3_layer_0();
	int value_2 = fct_reload_value_3_layer_1();
	fct_reload_value_3_reset();
	return (value_0 + value_1);
}

int fct_reload_value_3_layer_3()
{
	int value_2 = fct_reload_value_3_layer_2();//2005
	int value_1 = fct_reload_value_3_layer_1();
	return (value_2 + value_1);//3010
}

int fct_reload_value_3_layer_4()
{
	int value_3 = fct_reload_value_3_layer_3();
	fct_reload_value_3_reset();
	int value_0 = fct_reload_value_3_layer_0();
	return (value_3 + value_0); //4010
}

int fct_reload_value_3_calculation()
{
	int value = 1;
	int value_4 = fct_reload_value_3_layer_4();
	fct_reload_value_3_reset();
	return (value_4 + value);
}

void fct_reload_value_3_block_memory(void)
{
	//int val = fct_reload_value_3;
	fct_reload_value_3++;
	//fct_reload_value_3 = val;
}

int fct_reload_missed_symbol_get_missed_symbol()
{
	return missed_symbol;
}

int fct_reload_missed_symbol_get_value_1()
{
	int value = 100;
	value++;
	value--;
	return value;
	//RUN 1: Caller:fct_1
}

int fct_reload_missed_symbol_get_value_2()
{
	int value = 200;
	value++;
	value--;
	return value;
	//RUN 1: Caller: fct_1
}

int fct_reload_missed_symbol_get_value_3()
{
	int value = 400;
	value++;
	value--;
	return value;
	//RUN 2: Caller: fct_1
}

int fct_reload_missed_symbol_fct_1()
{
	int value_1 = fct_reload_missed_symbol_get_value_1();
	int value_2 = fct_reload_missed_symbol_get_value_2();
	//At this point we got 2 Subcall_t entries (value_1 value_2)
	int missed_value = fct_reload_missed_symbol_get_missed_symbol();
	int value_3 = fct_reload_missed_symbol_get_value_3();
	int value_4 = fct_reload_missed_symbol_get_value_1();
	//At this point we got 4 Subcall_t entries
	return value_1 + value_2 + value_3 + value_4 + missed_value; // 2137
}

int fct_reload_missed_symbol_init()
{
	return fct_reload_missed_symbol_fct_1();
}

////////////////////////////////////////////////////////////////////////////////////////////
int fct_blocked_sn_1(int val)
{
	return (val + 1);
}

int fct_blocked_sn(void *ptr)
{
	unsigned int val = (unsigned int) (long)ptr;
	val = fct_blocked_sn_1(val);
	return val;
}

int fct_blocked_snsn(void *ptr)
{
	unsigned int val = fct_blocked_sn(ptr);
	val++;
	return val;
}

int fct_blocked_fct_2(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_3_1(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_3_2_1(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_3_2_2(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_3_2(int ptr)
{
	int a = fct_blocked_fct_3_2_1(ptr);
	int b = fct_blocked_fct_3_2_2(ptr);
	int val = ptr;
	val++;
	return (val + a + b);
}

int fct_blocked_fct_3_3(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_3(int ptr)
{
	int a = fct_blocked_fct_3_1(ptr);
	int b = fct_blocked_fct_3_2(ptr);
	int c = fct_blocked_fct_3_3(ptr);
	int val = ptr;
	val++;
	return (val + a + b + c);
}

int fct_blocked_fct_4_1(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_4_2_1(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_4_2_2(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_4_2(int ptr)
{
	int a = fct_blocked_fct_4_2_1(ptr);
	int b = fct_blocked_fct_4_2_2(ptr);
	int val = ptr;
	val++;
	return (val + a + b);
}

int fct_blocked_fct_4_3(int ptr)
{
	int val = ptr;
	val++;
	return val;
}

int fct_blocked_fct_4(int ptr)
{
	int a = fct_blocked_fct_4_1(ptr);
	int b = fct_blocked_fct_4_2(ptr);
	int c = fct_blocked_fct_4_3(ptr);
	int val = ptr;
	val++;
	return (val + a + b + c);
}

int fct_blocked_init(void *ptr)
{
	int _ptr = (int) (long)ptr;
	int a = fct_blocked_fct_2(_ptr);
	int b = fct_blocked_fct_3(_ptr);
	int c = fct_blocked_fct_4(_ptr);
	int d = fct_blocked_fct_3_3(_ptr);
	int e = fct_blocked_fct_4_3(_ptr);
	_ptr++;
	return (_ptr + a + b + c + d + e);
}
////////////////////////////////////////////////////////////////////////////////////////////
/*extern int memcpy(void*,void*,unsigned long int);
extern void* malloc(unsigned long int);
extern void free(void*);*/
int static fct_sgx_call_value_0 = 999;
int fct_sgx_call_value_1 = 1000;
int *fct_sgx_call_get_value_0_val = 0, *fct_sgx_call_get_value_1_val = 0;

static int fct_sgx_call_get_value_0()
{
	fct_sgx_call_get_value_0_val = (int *) malloc(sizeof(int));
	memcpy(fct_sgx_call_get_value_0_val, &fct_sgx_call_value_0, sizeof(int));
	return *fct_sgx_call_get_value_0_val;
}

int fct_sgx_call_get_value_1()
{
	fct_sgx_call_get_value_1_val = (int *) malloc(sizeof(int));
	memcpy(fct_sgx_call_get_value_1_val, &fct_sgx_call_value_1, sizeof(int));
	return *fct_sgx_call_get_value_1_val;
}

void fct_sgx_call_init(test_fct_sgx_call_t *ptr)
{
	ptr->fct_sgx_call_value_0 = (int*)(long)fct_sgx_call_get_value_0();
	ptr->fct_sgx_call_value_1 = (int*)(long)fct_sgx_call_get_value_1();
	ptr->fct_sgx_call_value_0_addr = fct_sgx_call_get_value_0_val;
	ptr->fct_sgx_call_value_1_addr = fct_sgx_call_get_value_1_val;
	free(fct_sgx_call_get_value_0_val);
	free(fct_sgx_call_get_value_1_val);
}

////////////////////////////////////////////////////////////////////////////////////////////
void _init_test(test_cases_t *ptr)
{
	char *asd = 0;// <---- SegFault fix @ clang
	global_variables(ptr);
	static_variables(ptr);
	const_variables(ptr);
	static_const_variables(ptr);
	volatile_variables(ptr);
	static_volatile_variables(ptr);
	ptr->fct_test_register_a = 1;
	ptr->fct_test_register_b = 4;
	ptr->fct_test_register_c = fct_test_register(ptr->fct_test_register_a, ptr->fct_test_register_b);
	ptr->static_fct_test_a = 3;
	ptr->static_fct_test_b = 2;
	ptr->static_fct_test_c = static_fct_test(ptr);
}
