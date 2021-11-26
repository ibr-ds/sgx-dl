#ifndef PA_LIBRARY_MEMORY_ALLOCATOR_H
#define PA_LIBRARY_MEMORY_ALLOCATOR_H

#include "pa.h"
#include "pa_error.h"

#include <stddef.h>

#ifndef MEMORY_PAGE_SIZE
#define MEMORY_PAGE_SIZE 4096
#endif

#ifndef MEMORY_PAGES
#define MEMORY_PAGES (get_rsrv_size()/MEMORY_PAGE_SIZE)
#endif

#ifndef MINIMUM_MALLOC_SIZE
#define MINIMUM_MALLOC_SIZE 64
#endif

#if !__DL_ASLR

typedef enum
{
	memory_not_in_use = 0,
	memory_in_use = 1
} _mem_status_t;

typedef struct __mem_ctl
{
	struct __mem_ctl *pred, *succ;
	size_t size;
	_mem_status_t status;
} _pa_mem_ctl_t;

#else

typedef enum
{
	memory_not_in_use = 0,
	memory_in_use = 1
} _mem_status_t;

typedef struct __mem_ctl
{
	struct __mem_ctl *pred, *succ;
	void *payload;
	size_t size;
	uint64_t page_index;
	_mem_status_t status;
} _pa_mem_ctl_t;

typedef enum
{
	page_unused = 0,
    page_used_code = 1,
	page_used_data = 2,
	page_linked_code = 3,
	page_linked_data = 4   //incase multiple pages are linked together

} _page_status_t;

typedef struct __page_ctl
{
	size_t page_free_size;
	_pa_mem_ctl_t *first_mem_ctl;
	_pa_mem_ctl_t *tail_mem_ctl;
	_page_status_t status;
} page_ctl_t;

#endif

typedef enum
{
	code = 1,
	data = 2
} _alloc_mem_type_t;

#define FLAG_CODE page_used_code
#define FLAG_DATA page_used_data

uint64_t _dl_gen_rand_in_range(uint64_t lower, uint64_t upper);

dl_status_t _pa_malloc_data(void **ptr, size_t size);
dl_status_t _pa_malloc_code(void **ptr, size_t size);

dl_status_t _pa_malloc(void **ptr, size_t size, _page_status_t alloc_flag);

dl_status_t _pa_free(void *ptr);

#endif //PA_LIBRARY_MEMORY_ALLOCATOR_H
