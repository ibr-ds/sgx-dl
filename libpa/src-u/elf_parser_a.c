#include "__debug.h"
#include "elf_parser_a.h"
//#include "../src-t/elf_parser.h"

int fd = -1;
elf_header_t *enclave_ptr = NULL;
size_t file_size = -1;

static dl_status_t elf_check_header(elf_header_t *header_ptr)
{
	if (header_ptr == NULL)
	{
		return PA_INVALID_POINTER;
	}
	if (header_ptr->ident[0] != magic_0 || header_ptr->ident[1] != magic_1 || header_ptr->ident[2] != magic_2 || header_ptr->ident[3] != magic_3)
	{
		return PA_NOT_AN_ELF;
	}
	if (header_ptr->ident[4] != elf_x86_64)
	{
		return PA_X86_ELF_NOT_SUPPORTED;
	}
	if (header_ptr->ident[5] != elf_lsb)
	{
		return PA_ELF_MSB_NOT_SUPPORTED;
	}
	return DL_SUCCESS;
}

dl_status_t _pa_get_symtab(elf_section_symtab_t *sections, char *enclave_path)
{
	struct stat file_st;
	elf_section_header_t *enclave_section_ptr, *temp_section;
	sections->symtab_section_header = 0x0;
	dl_status_t status;
	if ((fd = open(enclave_path, O_RDONLY)) < 0)
	{
		return PA_CANT_OPEN_FILE;
	}
	if (fstat(fd, &file_st) < 0)
	{
		if (close(fd) == -1)
		{
			return PA_CLOSE_FAILED;
		}
		fd = -1;
		return PA_CANT_CALCULATE_FILE_SIZE;
	}
	file_size = file_st.st_size;
#ifdef _DEBUG
	printf("Size: %lu Byte.\n", file_size);
#endif
	if ((enclave_ptr = (elf_header_t *) mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
	{
		if (close(fd) == -1)
		{
			return PA_CLOSE_FAILED;
		}
		fd = -1;
		return PA_MMAP_FAILED;
	}
	if ((status = elf_check_header(enclave_ptr)) != DL_SUCCESS)
	{
		if (munmap(enclave_ptr, file_size) == -1)
		{
			return PA_MUNMAP_FAILED;
		}
		if (close(fd) == -1)
		{
			return PA_CLOSE_FAILED;
		}
		fd = -1;
		enclave_ptr = NULL;
		return status;
	}
#ifdef _DEBUG
	debug_print_elf_header((void *) enclave_ptr);
#endif
	enclave_section_ptr = ((void *) enclave_ptr) + enclave_ptr->sectionHeaderOffset;
#ifdef _DEBUG
	//char *enclave_string_section = ((void *) enclave_ptr) + enclave_section_ptr[enclave_ptr->section_header_string_table_index].offset;
#endif
	for (int i = 0; (i < enclave_ptr->sectionHeaderCount) && (sections->symtab_section_header == 0x0); i++)
	{
		temp_section = &enclave_section_ptr[i];
#ifdef _DEBUG
		//debug_print_elf_section_header(temp_section, enclave_string_section, i);
#endif
		if (temp_section->type == section_type_symtab)
		{
			sections->symtab_section_header = temp_section;
			sections->symtab_section = ((void *) enclave_ptr) + temp_section->offset;
			sections->symtab_string_section = ((void *) enclave_ptr) + enclave_section_ptr[temp_section->link].offset;
			sections->symtab_string_section_length = (uint32_t) enclave_section_ptr[temp_section->link].size;
			break;
		}
	}
	if (sections->symtab_section_header == 0x0)
	{
		if (munmap(enclave_ptr, file_size) == -1)
		{
			return PA_MUNMAP_FAILED;
		}
		if (close(fd) == -1)
		{
			return PA_CLOSE_FAILED;
		}
		fd = -1;
		enclave_ptr = NULL;
		return PA_SYMTAB_NOT_FOUND;
	}
	return DL_SUCCESS;
}

dl_status_t _pa_unmap_enclave(void)
{
	if (fd == -1 && enclave_ptr == NULL)
	{
		return DL_SUCCESS;
	}
	if (enclave_ptr != NULL && file_size != -1)
	{
		if (munmap(enclave_ptr, file_size) == -1)
		{
			return PA_MUNMAP_FAILED;
		}
		enclave_ptr = NULL;
	}
	if (fd != -1)
	{
		if (close(fd) == -1)
		{
			return PA_CLOSE_FAILED;
		}
		fd = -1;
	}
	return DL_SUCCESS;
}
