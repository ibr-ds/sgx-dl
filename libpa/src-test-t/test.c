#include "test_structs.h"

/*typedef struct{
    int intern,global,_extern,extern_with_functions;
    char secret_message_1[10];
    char secret_message_2[10];
} test_struct_t;*/

char myString[] = {"HalloWelt"};
int value_a = 2018;
extern int value_b;
extern int value_c;
extern int local_section_bss;
extern int local_section_data;
extern myStruct_t myStruct_bss;
int get_int_a(){
	return value_a;
}
int get_int_b(){
	return value_b;
}
void get_secret_message(char* ptr){
	int i = 0;
	while(myString[i] != '\0'){
		ptr[i] = myString[i];
		i++;
	}
	ptr[i] = myString[i];
}
void fill_struct(void* args){
	test_struct_t* ptr = (test_struct_t*) args;
	ptr->global = get_int_a();
	ptr->extern_with_functions = get_int_b();
	get_secret_message((char *)&ptr->secret_message_1);
	ptr->_extern = value_c;
	local_section_bss = local_section_data;
	myStruct_bss.a = 1;
	myStruct_bss.b = 2;
	myStruct_bss.c = ((double)myStruct_bss.a/(double)myStruct_bss.b);
}
