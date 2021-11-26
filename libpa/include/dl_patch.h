#ifndef SGX_DL_DL_PATCH_H
#define SGX_DL_DL_PATCH_H

typedef int (*dl_state_transfer_fct_t)(void *_old, void *_new);

/**
 * This structure describes a patch.
 * All members are strings.
 * Each string should either be NULL or contain symbol names delimited by space
 */
typedef struct
{
	char *add_symbols;
	char *pre_update_state_transfer_functions;
	char *update_symbols;
	char *post_update_state_transfer_functions;
	char *remove_symbols; // Really needed? We clean up anyway...
} dl_patch_desc_t;

#endif //SGX_DL_DL_PATCH_H
