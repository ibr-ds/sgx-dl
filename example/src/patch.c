#include "loadable.h"
#include <stdlib.h>
extern int _counter;

#ifdef BASELINE
int othercounter = 1;
#else
extern int othercounter;
#endif

void ocall_print_string(char *str);

int anothercounter = 42;

void add_helper(void *pargs)
{
	args_add_t *args = (args_add_t *)pargs;

	args->result = args->a + args->b;
}

void *add(void *pargs)
{
	add_helper(pargs);

	_counter += othercounter;

	//ocall_print_string("Hello from C!\n");
	//ocall_print_string("And again!\n");


	anothercounter += _counter;

	return NULL;
}
