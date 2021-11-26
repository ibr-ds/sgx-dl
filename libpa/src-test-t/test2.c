#include "test_structs.h"
int value_b = 1337;
extern int secret_storage;
extern void _init_test(test_cases_t* ptr);
myStruct_t myStruct_section_common;

int _a(){
	myStruct_section_common.a = 1;
	myStruct_section_common.b = 2;
	myStruct_section_common.c = 0.55;
	if(myStruct_section_common.c == 0.55){
		myStruct_section_common.c += 1.3333;
	}
	return (myStruct_section_common.a + myStruct_section_common.b);
}

void insert_string(char* str, int length,char* destination){
	int i = 0;
	while(i < length){
		destination[i] = str[i];
		i++;
	}
	destination[i] = '\0';
}

//part of the static fct test performed in test_cases.c
static int static_fct_test(void){
	return value_b;
}

void fill_struct(void* args);

void _init(void* args){
	test_struct_t* ptr = (test_struct_t*) args;
	fill_struct(args);
	ptr->intern = _a();
	ptr->double_value = myStruct_section_common.c;
	insert_string("TESTSTR",8, (char*)&ptr->secret_message_2);
	insert_string("RDATATEST",10, (char*)&ptr->secret_message_3);
	insert_string("TESTSTR",8, (char*)&ptr->secret_message_4);
	secret_storage = _a();
	secret_storage += 4;
	_a();
	_init_test(&ptr->test_case);
	static_fct_test();
}
