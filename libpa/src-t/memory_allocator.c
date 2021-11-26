//#define DEBUG

#include <string.h>
#include <stdlib.h>
#include <sgx_trts.h>
#include "memory_allocator.h"
#include "__enclave.h"

//#include "sgx_rsrv_mem_mngr.h" // Sadly, this is not exposed in the SDK yet

#if !__DL_ASLR

static _pa_mem_ctl_t *_page_ptr = NULL;

dl_status_t _pa_malloc(void **ptr, size_t size)
{
	_pa_mem_ctl_t *mem_ctl_ptr;

	if (ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	if (size == 0)
	{
		return PA_MEMORY_INVALID_SIZE;
	}

	if (_page_ptr == NULL)
	{
		if ((_page_ptr = (_pa_mem_ctl_t *)sgx_alloc_rsrv_mem(get_rsrv_size())) == NULL)
		{
			abort();
		}

		// FIXME: before/after loading toggle x, don't do rwx all the time!
		sgx_status_t res = sgx_tprotect_rsrv_mem(_page_ptr, get_rsrv_size(), SGX_PROT_READ | SGX_PROT_WRITE | SGX_PROT_EXEC);
		if (res != SGX_SUCCESS)
		{
#ifdef DEBUG
			debug_print("Cant change page permissions");
#endif
			return PA_CANT_CHANGE_PAGE_PERMISSIONS;
		}

		_page_ptr->pred = NULL;
		_page_ptr->succ = NULL;
		_page_ptr->status = memory_not_in_use;
		_page_ptr->size = get_rsrv_size() - sizeof(_pa_mem_ctl_t);
#ifdef DEBUG
		debug_print_mem_ctl_t(_page_ptr);
#endif
	}

	mem_ctl_ptr = _page_ptr;
	while (mem_ctl_ptr != NULL)
	{
		if (mem_ctl_ptr->status == memory_not_in_use && mem_ctl_ptr->size == size)
		{
			goto MEM_SUCCESS;
		}
		else if (mem_ctl_ptr->status == memory_not_in_use && (mem_ctl_ptr->size >= size && mem_ctl_ptr->size <= (size + sizeof(_pa_mem_ctl_t))))
		{
			goto MEM_SUCCESS;
		}
		else if (mem_ctl_ptr->status == memory_not_in_use && mem_ctl_ptr->size > (size + sizeof(_pa_mem_ctl_t)))
		{
			_pa_mem_ctl_t *temp_succ_ptr = mem_ctl_ptr->succ;
			mem_ctl_ptr->succ = ((void *) mem_ctl_ptr) + sizeof(_pa_mem_ctl_t) + size;
			mem_ctl_ptr->succ->pred = mem_ctl_ptr;
			mem_ctl_ptr->succ->succ = temp_succ_ptr;
			mem_ctl_ptr->succ->status = memory_not_in_use;
			mem_ctl_ptr->succ->size = mem_ctl_ptr->size - (size + sizeof(_pa_mem_ctl_t));
			mem_ctl_ptr->size = size;

			if (temp_succ_ptr != NULL)
			{
				temp_succ_ptr->pred = mem_ctl_ptr->succ;
			}

			goto MEM_SUCCESS;
		}

		mem_ctl_ptr = mem_ctl_ptr->succ;
	}

	return PA_MEMORY_NO_FREE_SPACE_FOUND;
	MEM_SUCCESS:
	mem_ctl_ptr->status = memory_in_use;
	*ptr = ((void *) mem_ctl_ptr) + sizeof(_pa_mem_ctl_t);
#ifdef DEBUG
	debug_print_mem_ctl_t(mem_ctl_ptr);
#endif
	return DL_SUCCESS;
}

dl_status_t _pa_free(void *ptr)
{
	if (ptr == NULL)
	{
		return PA_MEMORY_INVALID_POINTER;
	}

	_pa_mem_ctl_t *mem_ctl_ptr = ptr - sizeof(_pa_mem_ctl_t);

	if (mem_ctl_ptr->status == memory_not_in_use)
	{
		return PA_MEMORY_MEMORY_NOT_IN_USE;
	}

	if (mem_ctl_ptr->status != memory_in_use)
	{
		return PA_MEMORY_INVALID_POINTER;
	}

	if ((mem_ctl_ptr->pred != NULL && mem_ctl_ptr->pred->status == memory_not_in_use) && (mem_ctl_ptr->succ != NULL && mem_ctl_ptr->succ->status == memory_not_in_use))
	{
		mem_ctl_ptr->pred->succ = mem_ctl_ptr->succ->succ;

		if (mem_ctl_ptr->pred->succ != NULL)
		{
			mem_ctl_ptr->pred->succ->pred = mem_ctl_ptr->pred;
		}

		mem_ctl_ptr->pred->size += mem_ctl_ptr->size + mem_ctl_ptr->succ->size + 2 * sizeof(_pa_mem_ctl_t);
		mem_ctl_ptr = mem_ctl_ptr->pred;
	}
	else if (mem_ctl_ptr->pred != NULL && mem_ctl_ptr->pred->status == memory_not_in_use)
	{
		mem_ctl_ptr->pred->succ = mem_ctl_ptr->succ;

		if (mem_ctl_ptr->succ != NULL)
		{
			mem_ctl_ptr->succ->pred = mem_ctl_ptr->pred;
		}

		mem_ctl_ptr->pred->size += mem_ctl_ptr->size + sizeof(_pa_mem_ctl_t);
		mem_ctl_ptr = mem_ctl_ptr->pred;
	}
	else if (mem_ctl_ptr->succ != NULL && mem_ctl_ptr->succ->status == memory_not_in_use)
	{
		mem_ctl_ptr->size += mem_ctl_ptr->succ->size + sizeof(_pa_mem_ctl_t);
		mem_ctl_ptr->status = memory_not_in_use;

		if (mem_ctl_ptr->succ->succ != NULL)
		{
			mem_ctl_ptr->succ->succ->pred = mem_ctl_ptr;
		}

		mem_ctl_ptr->succ = mem_ctl_ptr->succ->succ;
	}
	else
	{
		mem_ctl_ptr->status = memory_not_in_use;
	}

#ifdef DEBUG
	if(mem_ctl_ptr->pred != NULL)
		debug_print_mem_ctl_t(mem_ctl_ptr->pred);
	debug_print_mem_ctl_t(mem_ctl_ptr);
	if(mem_ctl_ptr->succ != NULL)
		debug_print_mem_ctl_t(mem_ctl_ptr->succ);
#endif

	memset((void *) mem_ctl_ptr + sizeof(_pa_mem_ctl_t), 0, mem_ctl_ptr->size);

	return DL_SUCCESS;
}

#else

static page_ctl_t *mem_page_list;
static size_t total_reserved_mem_size = 0;
static int mem_pages = 0;
static void *payload_chain_ptr = NULL;


uint64_t _dl_gen_rand_in_range(uint64_t lower, uint64_t upper)
{
	uint64_t val = 0;
	if (sgx_read_rand((unsigned char *) &val, 8) != SGX_SUCCESS)
	{
		abort();
	}
	uint64_t result = (val % (upper - lower + 1)) + lower;
	return result;
}

dl_status_t check_page_fragmentation(uint64_t page_index, size_t desired_size)
{
	_pa_mem_ctl_t *mem_ctl_ptr = mem_page_list[page_index].first_mem_ctl;
	while (mem_ctl_ptr != NULL)
	{
		if(mem_ctl_ptr->status == memory_not_in_use && mem_ctl_ptr->size >= desired_size) return DL_SUCCESS;
		mem_ctl_ptr = mem_ctl_ptr->succ;
	}
	return PA_MEMORY_NO_FREE_SPACE_FOUND; //ToDo return special fragmented error status

}

dl_status_t check_random_page(uint64_t rand_page_index, size_t desired_size, _page_status_t alloc_flag)
{
	size_t rest = desired_size % MEMORY_PAGE_SIZE;
	size_t pages_needed = (desired_size / MEMORY_PAGE_SIZE);
	int check_counter = 0;

	if(pages_needed == 0)
	{
	    _page_status_t rand_page_status = mem_page_list[rand_page_index].status;
		if(rand_page_status != page_unused && rand_page_status != alloc_flag)
		{
			return PA_INCOMPATIBLE_PAGE_TYPE;
		}

		if(mem_page_list[rand_page_index].page_free_size >= desired_size)
		{
			// check if the page is fragmented such that it has the desired size but not sequentially
			return check_page_fragmentation(rand_page_index, desired_size);
		}
		return PA_MEMORY_NO_FREE_SPACE_FOUND;

	}
	else
	{
		pages_needed += rest == 0 ? 0 : 1;

		if (rand_page_index + pages_needed >= MEMORY_PAGES)
		{
			return PA_MEMORY_NO_FREE_SPACE_FOUND;
		}

		for (size_t i = 0; i < pages_needed; i++)  //in case pages needed are less than 1, this loop will be ignored
		{
			check_counter += mem_page_list[rand_page_index + i].status == page_unused ? 0 : 1;
		}

		return check_counter == 0 ? DL_SUCCESS : PA_MEMORY_NO_FREE_SPACE_FOUND;
	}
}

#define RAND_ITERATIONS 1000
dl_status_t get_random_page(size_t desired_size, uint64_t *result_page_index, _page_status_t alloc_flag)
{
	dl_status_t status = PA_MEMORY_NO_FREE_SPACE_FOUND;
	int counter = 0;
	uint64_t rand_page_index = _dl_gen_rand_in_range(0, mem_pages -1); // we want page indexes between 0 and (number of pages - 1)

	while (status != DL_SUCCESS && counter != RAND_ITERATIONS)
	{
		status = check_random_page(rand_page_index, desired_size, alloc_flag);
		counter++;
	}
	if(status == DL_SUCCESS)
	{
		*result_page_index = rand_page_index;
		return status;
	}
	for(size_t i = mem_pages/2, j = mem_pages/2 + 1; i >= 0 && j < mem_pages; i++, j++)
	{
		if(check_random_page(i, desired_size, alloc_flag) == DL_SUCCESS)
		{
			*result_page_index = i;
			return DL_SUCCESS;
		}
		if(check_random_page(j, desired_size, alloc_flag) == DL_SUCCESS)
		{
            *result_page_index = j;
            return DL_SUCCESS;
		}
	}
	// extend this eventually in case of hard fragmentation. i.e. check if sum of free page sizes is bigger than the desired size and throw appropriate new error
	return PA_MEMORY_NO_FREE_SPACE_FOUND;


}

dl_status_t _pa_mem_init()
{
	if(mem_page_list == NULL)
	{
	    mem_pages = MEMORY_PAGES;
	    total_reserved_mem_size = get_rsrv_size();
		if((mem_page_list = (page_ctl_t *) calloc(mem_pages, sizeof(page_ctl_t))) == NULL)
		{
#ifdef DEBUG
			debug_print("couldn't malloc memory for the pages");
#endif
			abort();
		}
	}

	if (payload_chain_ptr == NULL)
	{
		if ((payload_chain_ptr = sgx_alloc_rsrv_mem(total_reserved_mem_size)) == NULL)
		{
			abort();
		}

		// FIXME: remove this and actually set/remove permission on load/unload
		sgx_status_t res = sgx_tprotect_rsrv_mem(payload_chain_ptr, total_reserved_mem_size, SGX_PROT_READ | SGX_PROT_WRITE | SGX_PROT_EXEC);
		if(res != SGX_SUCCESS)
		{
#ifdef DEBUG
			debug_print("Cant change page permissions");
#endif
			return PA_CANT_CHANGE_PAGE_PERMISSIONS;
		}

		// Page initialisation
		for(size_t i = 0; i < mem_pages; i++)
		{
			mem_page_list[i].status = page_unused;
			mem_page_list[i].page_free_size = MEMORY_PAGE_SIZE;   //at first all pages are empty and have full page size
			if((mem_page_list[i].tail_mem_ctl = mem_page_list[i].first_mem_ctl = (_pa_mem_ctl_t *) calloc(1, sizeof(_pa_mem_ctl_t))) == NULL)
			{
				abort();
			}
			mem_page_list[i].first_mem_ctl->page_index = i;
			mem_page_list[i].first_mem_ctl->pred = NULL;
			mem_page_list[i].first_mem_ctl->succ = NULL;
			mem_page_list[i].first_mem_ctl->size = MEMORY_PAGE_SIZE;
			mem_page_list[i].first_mem_ctl->status = memory_not_in_use;
			mem_page_list[i].first_mem_ctl->payload = payload_chain_ptr + (i * MEMORY_PAGE_SIZE);
		}
	}
	return DL_SUCCESS;
}

dl_status_t _pa_malloc_data(void **ptr, size_t size)
{
	return _pa_malloc(ptr, size, FLAG_DATA);
}

dl_status_t _pa_malloc_code(void **ptr, size_t size)
{
	return _pa_malloc(ptr, size, FLAG_CODE);
}


#define HEAD 0
#define TAIL 1

dl_status_t _pa_malloc(void **ptr, size_t realSize, _page_status_t alloc_flag)
{
	_pa_mem_ctl_t *mem_ctl_ptr = NULL;
	dl_status_t status = DL_SUCCESS;
	size_t size = (realSize < MINIMUM_MALLOC_SIZE) ? MINIMUM_MALLOC_SIZE : realSize;

	if (ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}

	if (realSize == 0)
	{
		return PA_MEMORY_INVALID_SIZE;
	}

	//ToDo: find an appropriate place to call the memory init function than here
	if((status = _pa_mem_init()) != DL_SUCCESS)
	{
		return status;
	}


	uint64_t rand_page_index = 0;
	dl_status_t rand_page_status = get_random_page(size, &rand_page_index, alloc_flag);
	if(rand_page_status != DL_SUCCESS)
	{
		return rand_page_status;
	}

	size_t rest = size % MEMORY_PAGE_SIZE;
	size_t pages_needed = (size / MEMORY_PAGE_SIZE);



	// ToDo check for the ability to reserve more than 2 pages behind each other for sizes bigger than a page size
	if(pages_needed == 0)
	{
	    mem_page_list[rand_page_index].status = alloc_flag;
		uint64_t direction = _dl_gen_rand_in_range(0,1);
		if(direction == HEAD)
		{
			mem_ctl_ptr = mem_page_list[rand_page_index].first_mem_ctl;
		}
		else
		{
			mem_ctl_ptr = mem_page_list[rand_page_index].tail_mem_ctl;
		}

		while (mem_ctl_ptr != NULL)
		{
			if (mem_ctl_ptr->status == memory_not_in_use && mem_ctl_ptr->size == size)
			{
				goto MEM_SUCCESS;
			}
			else if (mem_ctl_ptr->status == memory_not_in_use && mem_ctl_ptr->size > size)
			{
				if(direction == HEAD)
				{
					_pa_mem_ctl_t *temp_succ_ptr = mem_ctl_ptr->succ;

					if((mem_ctl_ptr->succ =  (_pa_mem_ctl_t *) malloc(sizeof(_pa_mem_ctl_t))) == NULL)
					{
						abort();
					}
					mem_ctl_ptr->succ->page_index = rand_page_index;
					mem_ctl_ptr->succ->pred = mem_ctl_ptr;
					mem_ctl_ptr->succ->succ = temp_succ_ptr;
					mem_ctl_ptr->succ->status = memory_not_in_use;
					mem_ctl_ptr->succ->size = mem_ctl_ptr->size - size;
					mem_ctl_ptr->size = size;
					mem_ctl_ptr->succ->payload = mem_ctl_ptr->payload + size; // the new successor has its payload_ptr moved by the newly added payload's size

					if (temp_succ_ptr != NULL)
					{
						temp_succ_ptr->pred = mem_ctl_ptr->succ;
					}
					else
					{
						mem_page_list[rand_page_index].tail_mem_ctl = mem_ctl_ptr->succ;
					}
				}
				else
				{
					_pa_mem_ctl_t *temp_pred_ptr = mem_ctl_ptr->pred;

					if((mem_ctl_ptr->pred =  (_pa_mem_ctl_t *) malloc(sizeof(_pa_mem_ctl_t))) == NULL)
					{
						abort();
					}
					mem_ctl_ptr->pred->page_index = rand_page_index;
					size_t old_free_size = mem_ctl_ptr->size;
					mem_ctl_ptr->pred->succ = mem_ctl_ptr;
					mem_ctl_ptr->pred->pred = temp_pred_ptr;
					mem_ctl_ptr->pred->status = memory_not_in_use;
					mem_ctl_ptr->pred->size = old_free_size - size;
					mem_ctl_ptr->size = size;
					// the new predecessor has its payload_ptr moved with the current one because it moves it self each time backwards
					mem_ctl_ptr->pred->payload = mem_ctl_ptr->payload;
					mem_ctl_ptr->payload = mem_ctl_ptr->payload + old_free_size - size;
					if (temp_pred_ptr != NULL)
					{
						temp_pred_ptr->succ = mem_ctl_ptr->pred;
					}
					else
					{
						mem_page_list[rand_page_index].first_mem_ctl = mem_ctl_ptr->pred;
					}
				}
				goto MEM_SUCCESS;

			}
			mem_ctl_ptr = direction == HEAD ? mem_ctl_ptr->succ : mem_ctl_ptr->pred;
		}

		return PA_MEMORY_NO_FREE_SPACE_FOUND;

		MEM_SUCCESS:
		mem_page_list[rand_page_index].page_free_size -= size;
		mem_ctl_ptr->status = memory_in_use;
		*ptr = mem_ctl_ptr->payload;
		return DL_SUCCESS;
	}
	else
	{
		_page_status_t p_status = alloc_flag == FLAG_CODE ? page_linked_code : page_linked_data;
		mem_ctl_ptr = mem_page_list[rand_page_index].first_mem_ctl;
		pages_needed += rest == 0 ? 0 : 1;
		for(int i = 0; i < pages_needed; i++)
		{
			mem_page_list[rand_page_index + i].page_free_size = 0;
			mem_page_list[rand_page_index + i].status = p_status;
		}
		mem_ctl_ptr->status = memory_in_use;
		mem_ctl_ptr->size = size;

		*ptr = mem_ctl_ptr->payload;
		return DL_SUCCESS;
	}

}



_pa_mem_ctl_t *find_owner_mem_ctl_t(void *ptr)
{
    // security check if the given pointer outside the reserved dynamic memory range
	if( ((uint64_t)ptr < (uint64_t)payload_chain_ptr) || ((uint64_t)ptr > (uint64_t)payload_chain_ptr + total_reserved_mem_size) )
	{
		return NULL;
	}

	// Math = the desired ptr is >= payload_chain_ptr so the difference must be >= 0 and then we divide by the size of the page in order to get that page's index
	uint64_t page_index = ((uint64_t)ptr - (uint64_t)payload_chain_ptr) / (MEMORY_PAGE_SIZE); //(update: with memory_page_size -1, it causes no owner found cases)
	_pa_mem_ctl_t *mem_ctl_ptr_head = mem_page_list[page_index].first_mem_ctl;
	_pa_mem_ctl_t *mem_ctl_ptr_tail = mem_page_list[page_index].tail_mem_ctl;

	while (mem_ctl_ptr_head != NULL || mem_ctl_ptr_tail != NULL)
	{
		if(mem_ctl_ptr_head != NULL)
		{
			if(mem_ctl_ptr_head->payload == ptr) return mem_ctl_ptr_head;
			mem_ctl_ptr_head = mem_ctl_ptr_head->succ;
		}

		if(mem_ctl_ptr_tail != NULL)
		{
			if(mem_ctl_ptr_tail->payload == ptr) return mem_ctl_ptr_tail;
			mem_ctl_ptr_tail = mem_ctl_ptr_tail->pred;
		}
	}
	return NULL;
}

dl_status_t _pa_free(void *ptr)
{
	if (ptr == NULL)
	{
		return PA_MEMORY_INVALID_POINTER;
	}

	_pa_mem_ctl_t *mem_ctl_ptr = find_owner_mem_ctl_t(ptr);

	if (mem_ctl_ptr == NULL)
	{
		return PA_MEMORY_INVALID_POINTER;
	}

	if (mem_ctl_ptr->status == memory_not_in_use)
	{
		return PA_MEMORY_MEMORY_NOT_IN_USE;
	}

	memset(mem_ctl_ptr->payload, 0, mem_ctl_ptr->size);

	_pa_mem_ctl_t *cur_mem_ctl_pred = mem_ctl_ptr->pred;
	_pa_mem_ctl_t *cur_mem_ctl_succ = mem_ctl_ptr->succ;
	_pa_mem_ctl_t *cur_mem_ctl = mem_ctl_ptr;

	size_t rest = mem_ctl_ptr->size % MEMORY_PAGE_SIZE;
	size_t pages_freed = (mem_ctl_ptr->size / MEMORY_PAGE_SIZE);
	if(mem_page_list[cur_mem_ctl->page_index].status == page_linked_code || mem_page_list[cur_mem_ctl->page_index].status == page_linked_data)
	{
		pages_freed += rest == 0 ? 0 : 1;
		for (size_t i = 0; i < pages_freed; i++)
		{
			mem_page_list[cur_mem_ctl->page_index + i].page_free_size = MEMORY_PAGE_SIZE;
			mem_page_list[cur_mem_ctl->page_index + i].status = page_unused;
		}
		cur_mem_ctl->size = MEMORY_PAGE_SIZE;
		cur_mem_ctl->status = memory_not_in_use;
		return DL_SUCCESS;
	}


	mem_page_list[cur_mem_ctl->page_index].page_free_size += cur_mem_ctl->size;
	if(mem_page_list[cur_mem_ctl->page_index].page_free_size == MEMORY_PAGE_SIZE)
	{
		mem_page_list[cur_mem_ctl->page_index].status = page_unused;
	}

	// The freed space is in between two free spaces
	if ((cur_mem_ctl_pred != NULL && cur_mem_ctl_pred->status == memory_not_in_use)
		 && (cur_mem_ctl_succ != NULL && cur_mem_ctl_succ->status == memory_not_in_use))
	{
		cur_mem_ctl_pred->succ = cur_mem_ctl_succ->succ;
		mem_ctl_ptr->status = memory_not_in_use;

		if (cur_mem_ctl_pred->succ != NULL)
		{
			cur_mem_ctl_pred->succ->pred = cur_mem_ctl_pred;
		}

		cur_mem_ctl_pred->size += cur_mem_ctl->size + cur_mem_ctl_succ->size;
		mem_ctl_ptr = cur_mem_ctl_pred;
		if(cur_mem_ctl_succ == 	mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl)
		{
			mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl = mem_ctl_ptr;
		}
		free(cur_mem_ctl_succ);
		free(cur_mem_ctl);
		cur_mem_ctl_succ = NULL;
		cur_mem_ctl = NULL;
	}
	// The freed space has a free predecessor space
	else if (cur_mem_ctl_pred != NULL && cur_mem_ctl_pred->status == memory_not_in_use)
	{
		cur_mem_ctl_pred->succ = cur_mem_ctl_succ;
		mem_ctl_ptr->status = memory_not_in_use;

		if (cur_mem_ctl_succ != NULL)
		{
			cur_mem_ctl_succ->pred = cur_mem_ctl_pred;
		}

		cur_mem_ctl_pred->size += cur_mem_ctl->size;
		mem_ctl_ptr = cur_mem_ctl_pred;
		if(cur_mem_ctl == mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl)
		{
			mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl = mem_ctl_ptr;
		}
		free(cur_mem_ctl);
		cur_mem_ctl = NULL;
	}
	// The freed space has a free successor space
	else if (cur_mem_ctl_succ != NULL && cur_mem_ctl_succ->status == memory_not_in_use)
	{
		mem_ctl_ptr->size += cur_mem_ctl_succ->size;
		mem_ctl_ptr->status = memory_not_in_use;

		if (cur_mem_ctl_succ->succ != NULL)
		{
			cur_mem_ctl_succ->succ->pred = mem_ctl_ptr;
		}

		mem_ctl_ptr->succ = mem_ctl_ptr->succ->succ;
		if(cur_mem_ctl_succ == mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl)
		{
			mem_page_list[cur_mem_ctl->page_index].tail_mem_ctl = mem_ctl_ptr;
		}
		free(cur_mem_ctl_succ);
		cur_mem_ctl_succ = NULL;
	}
	// The freed space is root and has neither successor nor predecessor
	else
	{
		mem_ctl_ptr->status = memory_not_in_use;
	}


#ifdef DEBUG
	if(mem_ctl_ptr->pred != NULL)
		debug_print_mem_ctl_t(mem_ctl_ptr->pred);
	debug_print_mem_ctl_t(mem_ctl_ptr);
	if(mem_ctl_ptr->succ != NULL)
		debug_print_mem_ctl_t(mem_ctl_ptr->succ);
#endif

	return DL_SUCCESS;
}


#endif
