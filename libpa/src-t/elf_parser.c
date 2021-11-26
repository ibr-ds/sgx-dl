//
// Created by joshua on 19.10.18.
//

#include "elf_parser.h"

#include <stddef.h>
#include <string.h>

dl_status_t elf_check_header(void *file)
{
	if (file == NULL)
	{
		return PA_INVALID_POINTER;
	}
	elf_header_t *header = (elf_header_t *) file;
	if (header->ident[0] != magic_0 || header->ident[1] != magic_1 || header->ident[2] != magic_2 || header->ident[3] != magic_3)
	{
		return PA_NOT_AN_ELF;
	}
	if (header->ident[4] != elf_x86_64)
	{
		return PA_X86_ELF_NOT_SUPPORTED;
	}
	if (header->ident[5] != elf_lsb)
	{
		return PA_ELF_MSB_NOT_SUPPORTED;
	}
	return DL_SUCCESS;
}

void elf_get_section_data(void *destination, Elf_DWord data_size, Elf_Off offset, void *file)
{
	void *data_offset = file + offset;
	memcpy(destination, data_offset, data_size);
}
