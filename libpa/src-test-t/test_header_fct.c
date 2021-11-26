#include "test_header.h"
int test_header_int = 1337;
int test_header_int_fct = 999;
char test_header_string[] = {"Test_Header"};
int test_header_secret_calculation(int a, int b){
	return a+b;
}
void test_header_get_string(char* ptr){
	int counter = 0;
	while(test_header_string[counter] != '\0'){
		ptr[counter] = test_header_string[counter];
		counter++;
	}
	ptr[counter] = test_header_string[counter];
	return;
}
