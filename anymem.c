/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2023-2024 Joe van Tunen <joevt@shaw.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * Read physical memory range.
 */

#include <stdlib.h>
#include <strings.h>
#include "programmer.h"
#include "hwaccess_physmap.h"
#include "hwaccess_x86_io.h"
#include "platform/pci.h"
#include "platform.h"

struct anymem_data {
	uint8_t *virt_addr;
	uintptr_t phys_addr;
	int size;
};

static const struct dev_entry anymem_devs[] = {
	{-1, -1, OK, "Any PCI Vendor", "Any PCI Device"},

	{0,0,0,0,0},
};

static int anymem_probe(struct flashctx *flash)
{
	const struct anymem_data *data = flash->mst->opaque.data;

	flash->chip->total_size = (data->size + 1023) / 1024;
	flash->chip->total_bytes = data->size;
	flash->chip->page_size = data->size;
	flash->chip->tested = (struct tested){ .probe = OK, .read = OK, .erase = NA, .write = NA, .wp = NA };
	flash->chip->gran = WRITE_GRAN_1BYTE_IMPLICIT_ERASE;
	flash->chip->block_erasers->eraseblocks[0].size = flash->chip->page_size;
	flash->chip->block_erasers->eraseblocks[0].count = 1;

	return 1;
}

static int anymem_read(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	const struct anymem_data *data = flash->mst->opaque.data;

	while (len > 0) {
		*(uint8_t*)buf = pci_mmio_readb(data->virt_addr + start);
		start += 1;
		len -= 1;
		buf += 1;
	}
	return 0;
}

static int anymem_write(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	return 0;
}

static int anymem_erase(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen)
{
	return 0;
}

static int anymem_shutdown(void *par_data)
{
	free(par_data);
	return 0;
}

static const struct opaque_master opaque_master_anymem = {
	.shutdown   = anymem_shutdown,
	.probe      = anymem_probe,
	.read       = anymem_read,
	.write      = anymem_write,
	.erase      = anymem_erase,
};

static int anymem_init(const struct programmer_cfg *cfg)
{
	uintptr_t phys_addr = 0;
	uint8_t *virt_addr = NULL;
	int size = 0;
	uint64_t address = 0;
	char *tmp;
	char *endptr;

	struct anymem_data *data = calloc(1, sizeof(*data));
	if (!data) {
		msg_perr("Unable to allocate space for PAR master data\n");
		return 1;
	}
	bzero(data, sizeof(*data));

	endptr = NULL;
	tmp = extract_programmer_param_str(cfg, "address");
	if (tmp) {
		address = (uint32_t)strtoull(tmp, &endptr, 0);
		if (!endptr || *endptr != '\0') {
			msg_perr("Invalid address. Specify the address like this: -p anymem:address=0xfff00000\n");
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	if (address == 0) {
		msg_perr("Invalid address. Specify the address like this: -p anymem:address=0xfff00000\n");
		free(tmp);
		anymem_shutdown(data);
		return 1;
	}

	endptr = NULL;
	tmp = extract_programmer_param_str(cfg, "size");
	if (tmp) {
		size = (int)strtoul(tmp, &endptr, 0);
		if (!endptr || *endptr != '\0' || size <= 0) {
			msg_perr("Invalid size. Specify the size like this: -p anymem:size=0x10000\n");
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	if (size <= 0) {
		msg_perr("Invalid size. Specify the size like this: -p anymem:size=0x10000\n");
		free(tmp);
		anymem_shutdown(data);
		return 1;
	}

	phys_addr = address;
	virt_addr = physmap_ro("Any physical memory region", phys_addr, size);
	if (virt_addr == ERROR_PTR) {
		anymem_shutdown(data);
		return 1;
	}

	data->virt_addr = virt_addr;
	data->phys_addr = phys_addr;
	data->size = size;
	return register_opaque_master(&opaque_master_anymem, data);
}

const struct programmer_entry programmer_anymem = {
	.name       = "anymem",
	.type       = OTHER,
	.devs.dev   = anymem_devs,
	.init       = anymem_init,
};
