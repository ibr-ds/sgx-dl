#include "loadable.h"
#include <stdlib.h>

extern int _counter;

int othercounter = 1;

static int woop = 56;

static void sub_helper(void *pargs)
{
	args_add_t *args = (args_add_t *)pargs;

	args->result = args->a - args->b;
}

void *add(void *pargs)
{
	sub_helper(pargs);

	_counter += othercounter;

	woop += _counter;

	return NULL;
}
