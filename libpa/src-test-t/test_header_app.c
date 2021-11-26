#include "test_header.h"
#include "test_structs.h"
extern int test_header_int;
extern int test_header_int_fct;
void test_header_main(test_header_args_t* ptr){
	ptr->test_header_int = test_header_int;
	ptr->test_header_secret_calculation = test_header_secret_calculation(5,5);
	ptr->test_header_int_fct = test_header_int_fct;
	test_header_get_string(ptr->test_header_string);
}
