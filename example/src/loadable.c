#include "loadable.h"
#include <stdlib.h>

int _counter = 0;

extern int othercounter;

void *add(void *pargs);

void *mul(void *pargs)
{
	args_add_t *args = (args_add_t *)pargs;

	args->result = args->a * args->b;

	return NULL;
}

void *bla(void *pargs)
{
	args_add_t *args = (args_add_t *)pargs;

	args_add_t a = { .a = args->a, .b = args->b };

	add(&a); // a + b

	a.a = a.result;

	mul(&a); // add(a + b) * b

	args->result = a.result;

	othercounter++;

//	for (int i = 0; i < 10; ++i)
//		__asm__("pause");

	return NULL;
}

void *getCounter(void *pargs)
{
	return (void*)_counter;
}

int other_signature(int a, int b, int c)
{
	return a + b + c;
}

#ifdef BENCHMARK

#define __FUNC(A) void *__func##A(void *args) { return NULL; }

#define __FUNC2(A) \
__FUNC(A##0) \
__FUNC(A##1) \
__FUNC(A##2) \
__FUNC(A##3) \
__FUNC(A##4) \
__FUNC(A##5) \
__FUNC(A##6) \
__FUNC(A##7) \
__FUNC(A##8) \
__FUNC(A##9)

#define __FUNC3(A) \
__FUNC2(A##0) \
__FUNC2(A##1) \
__FUNC2(A##2) \
__FUNC2(A##3) \
__FUNC2(A##4) \
__FUNC2(A##5) \
__FUNC2(A##6) \
__FUNC2(A##7) \
__FUNC2(A##8) \
__FUNC2(A##9)

#define FUNC(A) \
__FUNC3(A##0) \
__FUNC3(A##1) \
__FUNC3(A##2) \
__FUNC3(A##3) \
__FUNC3(A##4) \
__FUNC3(A##5) \
__FUNC3(A##6) \
__FUNC3(A##7) \
__FUNC3(A##8) \
__FUNC3(A##9)

FUNC(0)
FUNC(1)
FUNC(2)
FUNC(3)
FUNC(4)
FUNC(5)
FUNC(6)
FUNC(7)
FUNC(8)
FUNC(9)

#endif
