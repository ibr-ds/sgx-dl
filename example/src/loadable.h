#ifndef SGX_DL_LOADABLE_H
#define SGX_DL_LOADABLE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int a;
	int b;
	int result;
} args_add_t;

#ifdef BASELINE
void *bla(void *pargs);
#endif


#ifdef __cplusplus
};
#endif

#endif //SGX_DL_LOADABLE_H
