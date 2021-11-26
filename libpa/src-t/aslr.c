#include <string.h>

#include "pa.h"
#include "pa_error.h"
#include "rwlock.h"
#include "dynamic_functions_e.h"
#include "memory_allocator.h"
#include <math.h>

#include <sgx.h>
#include <sgx_trts.h>
#include <stdio.h>

#define cpu_relax() __asm__ volatile("pause": : :"memory")

#ifdef ASLR_IN_BAND
int64_t aslr_current_call_counter = 0;
#endif

extern char _dl_error_msg[1024];
extern _pa_fct_table_t *_fct_table;
extern _pa_file_table_t *_file_table;
extern _pa_obj_table_t *_obj_table;
extern rwlock_t table_lock;
void debug_printf(const char *fmt, ...);

#define RUNNING (1)
#define STOPPED (0)

static uint16_t shuffle_thread_state = RUNNING;
volatile int shuffling_state = 1000;				 //This will be incremented with a random number (capped) upon each successful shuffling and decremented after each dynamic function call
rwlock_t shuffling_lock = 0;

static void shuffled_array(int* result_array, int upperBound)
{
	for(int j = 0; j < upperBound; j++)
	{
		result_array[j] = j;
	}
	uint64_t val = 0;
	for (int i = upperBound-1; i >= 0; --i)
	{
		sgx_read_rand((unsigned char *) &val, 8);
		int j = val % (i+1);

		//swap the last element with element at random index
		int temp = result_array[i];
		result_array[i] = result_array[j];
		result_array[j] = temp;
	}
}

typedef struct {
	_pa_fct_table_t *fct_ptr;
	void *new_fct_addr;
	void *old_fct_addr;
} shuffled_fct_table_t;

static void * get_new_addr(shuffled_fct_table_t *shuffled_fcts, size_t shuff_fct_cnt, void *old_addr)
{
	for(int i = 0; i < shuff_fct_cnt; i++)
	{
		if(shuffled_fcts[i].old_fct_addr == old_addr)
		{
			return shuffled_fcts[i].new_fct_addr;
		}
	}
	return NULL;
}

static dl_status_t resolve_shuffled_functions(shuffled_fct_table_t *shuffled_fcts, size_t shuff_fct_cnt)
{
	dl_status_t status = DL_SUCCESS;
	_pa_fct_table_t *fct_ptr = NULL;
	void *fct_new_addr = NULL;
	for(int f = 0; f < shuff_fct_cnt; f++)
	{
		fct_ptr = shuffled_fcts[f].fct_ptr;
		fct_new_addr = shuffled_fcts[f].new_fct_addr;

		if (fct_ptr->resolved_relocations != NULL)
		{
			// This loop iterates through the rela section of the file the symbol that needs to be loaded is located in
			for (int i = 0; i < fct_ptr->relocation_entries; i++)
			{
				_pa_relocation_t *rel = &fct_ptr->resolved_relocations[i];
#ifdef DEBUG
				debug_print_elf_relocation(rel);
				//debug_print_elf_symbol(symbol,symbol_name);
#endif
				if (!rel->resolved)
				{
					//__asm__("ud2");
					snprintf(_dl_error_msg, sizeof(_dl_error_msg) - 1, "Unresolved relocation while loading %s: >%s< unresolved", fct_ptr->fct_name, rel->symbol_name);
					status = PA_UNRESOLVED_RELOCATION;
					goto END;
				}

				if (ELF_S_BIND(rel->symbol.info) == symbol_binding_global)
				{

#ifdef DEBUG
					//temp_string_table = found_file_table->string_table;//((void*)found_file_table->file_header) + found_file_table->section_header[found_file_table->symbol_table->link].offset;
					//debug_print("Symbol found:");
					//debug_print_elf_symbol(found_symbol, (char *)&temp_string_table[found_symbol->name_offset]);
#endif
					// At this point we found the global symbol that we need for our relocation
					// found_symbol contains the needed symbol
					// found_file_table the file it has been found in
					// Now we need to check the kind of relocation
					if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
					{
						// Needed symbol is an global object.
						// At this point temp_obj holds the found object
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_new_addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
					{
						// The needed symbol is a function.

						_pa_fct_table_t *temp_fct = rel->ref.fct;

						void *tmp_fct_new_addr = get_new_addr(shuffled_fcts, shuff_fct_cnt, temp_fct->addr);
						if(tmp_fct_new_addr == NULL)
						{
							//ocall_print("tmp fct new address not found!\n");
							abort();
						}
						// Do the actual relocation
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_new_addr + rel->elfrel.offset, &tmp_fct_new_addr, 0);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_enclave)
					{
						if ((status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_new_addr + rel->elfrel.offset, &rel->ref.encl_fct->addr, 0)) != DL_SUCCESS)
						{
							goto END;
						}
					}
					else // needed global symbol is neither function nor object
					{
						goto END;
					}
				} // global symbol end
				else if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
				{
					if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
					{
						// Needed local symbol is an local object
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->symbol.value + rel->elfrel.addend, fct_new_addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else if (ELF_S_TYPE(rel->symbol.info) == symbol_type_fct)
					{
						// Needed local symbol is a function

						_pa_fct_table_t *temp_fct = NULL;

						// Iterate over all symbols of the file
						temp_fct = rel->ref.fct;
#ifdef DEBUG
						debug_print_fct_table_t(temp_fct);
#endif

						void *tmp_fct_new_addr = get_new_addr(shuffled_fcts, shuff_fct_cnt, temp_fct->addr);
						if(tmp_fct_new_addr == NULL)
						{
							//ocall_print("tmp fct new address not found!\n");
							abort();
						}
						// We can now do our relocation
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_new_addr + rel->elfrel.offset, &tmp_fct_new_addr, 0);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else
					{
						status = PA_UNSUPPORTED_SYMBOL_TYPE;
						goto END;
					}
				} // local symbol end
				else
				{
					// It is neither a local nor global symbol, we cannot work with that
					status = PA_UNSUPPORTED_SYMBOL_BINDING;
					goto END;
				}
			}

		} // Done resolving relocations
	}
	/*if (fct_ptr->parent_relocations != NULL)
	{
		_pa_parent_relocation_t *it = fct_ptr->parent_relocations;
		while (it != NULL)
		{
			if (_PA_FCT_IS_LOADED(it->parent->status))
			{
				_pa_relocation(ELF_R_TYPE(it->rel->elfrel.info), it->rel->elfrel.addend, it->parent->addr + it->rel->elfrel.offset, &it->rel->ref.fct->addr, 0);
			}
			it = it->next;
		}
	}*/

	END:
	return status;
}

static dl_status_t resolve_shuffled_objects(shuffled_fct_table_t *shuffled_fcts, size_t shuff_fct_cnt)
{
	dl_status_t status = DL_SUCCESS;
	_pa_fct_table_t *fct_ptr = NULL;
	for(int f = 0; f < shuff_fct_cnt; f++)
	{
		fct_ptr = shuffled_fcts[f].fct_ptr;
		// If there are relocation entries, we have to resolve them
		if (fct_ptr->resolved_relocations != NULL)
		{
			// This loop iterates through the rela section of the file the symbol that needs to be loaded is located in
			for (int i = 0; i < fct_ptr->relocation_entries; i++)
			{
				_pa_relocation_t *rel = &fct_ptr->resolved_relocations[i];
#ifdef DEBUG
				debug_print_elf_relocation(rel);
#endif

				if (ELF_S_BIND(rel->symbol.info) == symbol_binding_global)
				{

#ifdef DEBUG
					//temp_string_table = found_file_table->string_table;//((void*)found_file_table->file_header) + found_file_table->section_header[found_file_table->symbol_table->link].offset;
					//debug_print("Symbol found:");
					//debug_print_elf_symbol(found_symbol, (char *)&temp_string_table[found_symbol->name_offset]);
#endif
					// At this point we found the global symbol that we need for our relocation
					// found_symbol contains the needed symbol
					// found_file_table the file it has been found in
					// Now we need to check the kind of relocation
					if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
					{
						// Needed symbol is an global object.

						// At this point temp_obj holds the found object
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else if (ELF_S_TYPE(rel->symbol.info) != symbol_type_fct && ELF_S_TYPE(rel->symbol.info) != symbol_type_enclave)
					{
						// needed global symbol is neither function nor object
						status = PA_UNSUPPORTED_SYMBOL_TYPE;
						goto END;
					}

				} // global symbol end
				else if (ELF_S_BIND(rel->symbol.info) == symbol_binding_local)
				{
					if (ELF_S_TYPE(rel->symbol.info) == symbol_type_obj)
					{
						// Needed local symbol is an local object
						status = _pa_relocation(ELF_R_TYPE(rel->elfrel.info), rel->symbol.value + rel->elfrel.addend, fct_ptr->addr + rel->elfrel.offset, &rel->ref.obj->addr, rel->ref.obj->alignment_offset);
						if (status != DL_SUCCESS)
						{
							goto END;
						}
					}
					else if (ELF_S_TYPE(rel->symbol.info) != symbol_type_fct)
					{
						// Needed local symbol is neither a function nor an object
						status = PA_UNSUPPORTED_SYMBOL_TYPE;
						goto END;
					}

				} // local symbol end
				else
				{
					// It is neither a local nor global symbol, we cannot work with that
					status = PA_UNSUPPORTED_SYMBOL_BINDING;
					goto END;
				}
			}
		}
	}// Done resolving relocations

	END:
	return status;
}


dl_status_t shuffle_object_tables()
{
	dl_status_t status = DL_SUCCESS;
	_pa_file_table_t *file_table_ptr = _file_table;
	_pa_obj_table_t *global_obj_table_ptr = _obj_table;
	_pa_obj_table_t *local_obj_table_ptr = NULL;
	void *old_addr = NULL;

	while(global_obj_table_ptr != NULL) {
		old_addr = global_obj_table_ptr->addr;
		if ((status = _pa_malloc_data(&global_obj_table_ptr->addr, global_obj_table_ptr->size + global_obj_table_ptr->alignment)) != DL_SUCCESS) {
			return status;
		}
		uint64_t new_alignment_offset = global_obj_table_ptr->alignment == 0 ? 0 : ((uint64_t)global_obj_table_ptr->addr) % global_obj_table_ptr->alignment;
		memcpy(global_obj_table_ptr->addr + new_alignment_offset, old_addr + global_obj_table_ptr->alignment_offset, global_obj_table_ptr->size);
		global_obj_table_ptr->alignment_offset = new_alignment_offset;
		if ((status = _pa_free(old_addr)) != DL_SUCCESS) {
			return status;
		}

		global_obj_table_ptr = global_obj_table_ptr->succ;
	}

	while(file_table_ptr != NULL)
	{
		local_obj_table_ptr = file_table_ptr->_local_obj_table;

		while(local_obj_table_ptr != NULL)
		{
			old_addr = local_obj_table_ptr->addr;
			if((status = _pa_malloc_data(&local_obj_table_ptr->addr, local_obj_table_ptr->size + local_obj_table_ptr->alignment)) != DL_SUCCESS)
			{
				return status;
			}
			uint64_t new_alignment_offset = local_obj_table_ptr->alignment == 0 ? 0 : ((uint64_t)local_obj_table_ptr->addr) % local_obj_table_ptr->alignment;
			memcpy(local_obj_table_ptr->addr + new_alignment_offset, old_addr + local_obj_table_ptr->alignment_offset, local_obj_table_ptr->size);
			local_obj_table_ptr->alignment_offset = new_alignment_offset;
			if((status = _pa_free(old_addr)) != DL_SUCCESS)
			{
				return status;
			}

			local_obj_table_ptr = local_obj_table_ptr->succ;
		}

		file_table_ptr = file_table_ptr->succ;
	}

	return status;
}

static uint64_t loaded_functions(_pa_fct_table_t *table)
{
	uint64_t sum = 0;
	_pa_fct_table_t *it = table;
	while (it != NULL)
	{
		if (_PA_FCT_IS_LOADED(it->status))
		{
			sum++;
		}
		it = it->succ;
	}
	return sum;
}

static uint64_t total_loaded_functions()
{
	uint64_t sum = 0;
	sum += loaded_functions(_fct_table);
	_pa_file_table_t *it = _file_table;
	while (it != NULL)
	{
		sum += loaded_functions(it->_fct_table);
		it = it->succ;
	}
	return sum;
}

static dl_status_t _pa_simult_fct_addr_shuffling()
{
	unlock_func unlock_table = read_unlock;
	dl_status_t status = DL_SUCCESS;

	read_lock(&table_lock);

	uint64_t cur_total_loaded_functions = total_loaded_functions();

	//debug_printf("shuffling %lu functions\n", cur_total_loaded_functions);

	if(cur_total_loaded_functions == 0)
	{
		unlock_table(&table_lock);
		return status;
	}

	shuffled_fct_table_t *to_shuff_fct_lst = (shuffled_fct_table_t *) calloc(cur_total_loaded_functions, sizeof(shuffled_fct_table_t));

	//first copy all functions including their old and new addresses
	_pa_fct_table_t *fct_it = _fct_table;
	int counter = 0;
	while (fct_it != NULL)
	{
		if (_PA_FCT_IS_LOADED(fct_it->status))
		{
			to_shuff_fct_lst[counter].fct_ptr = fct_it;
			to_shuff_fct_lst[counter].old_fct_addr = fct_it->addr;
			status = _pa_malloc_code(&to_shuff_fct_lst[counter].new_fct_addr, fct_it->opcode_size);
			if(status != SGX_SUCCESS)
			{
				//ToDo: probably do similar to _pa_find_func_memory in case no free space was found but for now the reserved place should fit everything
				goto END;
			}
			memcpy(to_shuff_fct_lst[counter].new_fct_addr, fct_it->addr, fct_it->opcode_size);
			counter++;
		}
		fct_it = fct_it->succ;
	}
	_pa_file_table_t *file_it = _file_table;
	while (file_it != NULL)
	{
		fct_it = file_it->_fct_table;
		while (fct_it != NULL)
		{
			if (_PA_FCT_IS_LOADED(fct_it->status))
			{
				to_shuff_fct_lst[counter].fct_ptr = fct_it;
				to_shuff_fct_lst[counter].old_fct_addr = fct_it->addr;
				status = _pa_malloc_code(&to_shuff_fct_lst[counter].new_fct_addr, fct_it->opcode_size);
				if(status != SGX_SUCCESS)
				{
					//ToDo: probably do similar to _pa_find_func_memory in case no free space was found but for now the reserved place should fit everything
					goto END;
				}
				memcpy(to_shuff_fct_lst[counter].new_fct_addr, fct_it->addr, fct_it->opcode_size);
				counter++;
			}
			fct_it = fct_it->succ;
		}
		file_it = file_it->succ;
	}

	// resolve the shuffled functions with the new addresses
	if((status = resolve_shuffled_functions(to_shuff_fct_lst, counter)) != DL_SUCCESS)
	{
		goto END;
	}

	// switch the functions addresses with the new ones
	for(uint64_t i = 0; i < counter; i++)
	{
		to_shuff_fct_lst[i].fct_ptr->addr = to_shuff_fct_lst[i].new_fct_addr;
	}

	//upgrade the read lock to write lock to gain sync moment in order to free the old addresses
	if (upgrade_trylock(&table_lock))
	{
		status = PA_UPGRADE_LOCK_ERROR;
		goto END;
	}
	unlock_table = write_unlock;

	/*
	 *  Iterate through each file_table entry and iterate their global and local object tables
	 * 	copy, switch and free each of the objects' addresses
	 * 	when finished call resolve_shuffled_objects
	 * 	unlock and you are free to go son (Jobs done)
	 */
	if((status = shuffle_object_tables()) != DL_SUCCESS)
	{
		goto END;
	}
	if((status = resolve_shuffled_objects(to_shuff_fct_lst, counter)) != DL_SUCCESS)
	{
		goto END;
	}

	unlock_table(&table_lock);



	for(uint64_t i = 0; i < counter; i++)
	{
		if( (status = _pa_free(to_shuff_fct_lst[i].old_fct_addr)) != DL_SUCCESS )
		{
			free(to_shuff_fct_lst);
			return status;
		}
	}

	free(to_shuff_fct_lst);
	return status;

	END:
	free(to_shuff_fct_lst);
	unlock_table(&table_lock);
	return status;
}


dl_status_t _dl_shuffle_fct_addresses()
{
	write_lock(&table_lock);
	dl_status_t status = DL_SUCCESS;

	uint64_t cur_total_loaded_functions = total_loaded_functions();

	if(cur_total_loaded_functions == 0)
	{
		write_unlock(&table_lock);
		return status;
	}

	_pa_fct_table_t **to_shuffle_fct_list = (_pa_fct_table_t**) calloc(cur_total_loaded_functions, sizeof(_pa_fct_table_t*));

	//first unload all functions
	_pa_fct_table_t *fct_it = _fct_table;
	int counter = 0;
	while (fct_it != NULL)
	{
		if (_PA_FCT_IS_LOADED(fct_it->status))
		{
			to_shuffle_fct_list[counter++] = fct_it;
			status = _pa_unload_fct_ex(fct_it);
			if(status != DL_SUCCESS)
			{
				goto END;
			}
		}
		fct_it = fct_it->succ;
	}
	_pa_file_table_t *file_it = _file_table;
	while (file_it != NULL)
	{
		fct_it = file_it->_fct_table;
		while (fct_it != NULL)
		{
			if (_PA_FCT_IS_LOADED(fct_it->status))
			{
				to_shuffle_fct_list[counter++] = fct_it;
				status = _pa_unload_fct_ex(fct_it);
				if(status != DL_SUCCESS)
				{
					goto END;
				}
			}
			fct_it = fct_it->succ;
		}
		file_it = file_it->succ;
	}

	if(counter != cur_total_loaded_functions)
	{
		status = PA_UNKNOWN_ERROR; //This should never happen as the counter should be the same as the number of loaded functions
		goto END;
	}

	
	if((status = shuffle_object_tables()) != DL_SUCCESS)
	{
		goto END;
	}
	//*/

	int* shuffled_index_array = (int *) calloc(counter, sizeof(int));
	shuffled_array(shuffled_index_array, counter);

	//load the functions again in a random order
	for(int i = 0; i < counter; i++)
	{
		int rand_index = shuffled_index_array[i];
		status = _pa_load_fct_ex(to_shuffle_fct_list[rand_index]);
		if(status != DL_SUCCESS)
		{
			free(shuffled_index_array);
			goto END;
		}
	}
	free(shuffled_index_array);

	END:
	/*
	if(shuffle_thread_state == STOPPED)
	{
		status = DL_SUCCESS;
	//*/
	free(to_shuffle_fct_list);
	write_unlock(&table_lock);
	//if the function table list is empty then nothing to do and return success
	return status;
}


#define LOWER_SHUFFLING_BOUND 1000
#define UPPER_SHUFFLING_BOUND 2000
#define SHUFFLING_INC_DEC_FACTOR 500
#define MAX_SHUFFLING_UPPER_BOUND 4000
#define MAX_SHUFFLING_LOWER_BOUND 3000
#define MIN_SHUFFLING_UPPER_BOUND 500
#define MIN_SHUFFLING_LOWER_BOUND 0
#define BUSY_WAITING_UPPER_BOUND 50000
#define BUSY_WAITING_FACTOR 10
#define BUSY_WAITING_START 5000


void ecall_dl_start_shuffling()
{
	int busy_waiting_variable = BUSY_WAITING_START;
	uint64_t shuff_lower_bound = LOWER_SHUFFLING_BOUND;
	uint64_t shuff_upper_bound = UPPER_SHUFFLING_BOUND;
	//int shuff_counter = 0;
	uint64_t rnd_inc = _dl_gen_rand_in_range(shuff_lower_bound, shuff_upper_bound);

	write_lock(&shuffling_lock);
	shuffling_state += rnd_inc;
	int old_shuffling_state = shuffling_state;
	write_unlock(&shuffling_lock);

	int exec_diff = 0;

	while(shuffle_thread_state)
	{

		for(uint64_t i = 0; i < busy_waiting_variable; i++)
		{
			cpu_relax();
		}
		if(_pa_simult_fct_addr_shuffling() != SGX_SUCCESS) // _pa_fct_addr_shuffling_cpy_swt_free
		{
			//ocall_print("shuffling function failed!\n");
			abort();
		}
		exec_diff = old_shuffling_state - shuffling_state;
		if(exec_diff > rnd_inc)
		{
			busy_waiting_variable = fmax(busy_waiting_variable - BUSY_WAITING_FACTOR, 0);
			shuff_lower_bound = fmin(shuff_lower_bound + SHUFFLING_INC_DEC_FACTOR, MAX_SHUFFLING_LOWER_BOUND);
			shuff_upper_bound = fmin(shuff_upper_bound + SHUFFLING_INC_DEC_FACTOR, MAX_SHUFFLING_UPPER_BOUND);
			//ocall_print("decreasing waiting time\n");
		}
		else
		{
			busy_waiting_variable = fmin(busy_waiting_variable + BUSY_WAITING_FACTOR, BUSY_WAITING_UPPER_BOUND);
			shuff_lower_bound = fmax(shuff_lower_bound - SHUFFLING_INC_DEC_FACTOR, MIN_SHUFFLING_LOWER_BOUND);
			shuff_upper_bound = fmax(shuff_upper_bound - SHUFFLING_INC_DEC_FACTOR, MIN_SHUFFLING_UPPER_BOUND);
			//ocall_print("increasing waiting time\n");
		}

		/*if(shuffling_state == 0 && fct_call_cnt_since_last_shuffle >= max_fct_calls_possible_since_last_shuffle)
		{
			snprintf(error_msg, sizeof(error_msg) - 1, "we are dying here and need to work!!! busy waiting var = %d \n", busy_waiting_variable);
			ocall_print(error_msg);
		}*/

		rnd_inc = _dl_gen_rand_in_range(shuff_lower_bound, shuff_upper_bound);
		write_lock(&shuffling_lock);
		old_shuffling_state = shuffling_state = fmin(shuffling_state + rnd_inc, MAX_SHUFFLING_STATE);
		write_unlock(&shuffling_lock);
		//ocall_print("unlocking dude\n");
		//shuff_counter++;
	}

}