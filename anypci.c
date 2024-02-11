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
 * Read config, ROM, or BAR of any PCI device.
 */

#include <stdlib.h>
#include <strings.h>
#include "programmer.h"
#include "hwaccess_physmap.h"
#include "hwaccess_x86_io.h"
#include "platform/pci.h"
#include "platform.h"

struct anypci_data {
	uint8_t *virt_addr;
	uintptr_t phys_addr;
	int size;
	struct pci_dev *dev;
	int bar;
	pci_bartype bartype;
	uint16_t supported_cycles_before, supported_cycles_after;
	uint32_t bar_addr_before, bar_addr_after;
	int width;
};

static const struct dev_entry anypci_devs[] = {
	{-1, -1, OK, "Any PCI Vendor", "Any PCI Device"},

	{0,0,0,0,0},
};

static int anypci_probe(struct flashctx *flash)
{
	const struct anypci_data *data = flash->mst->opaque.data;

	flash->chip->total_size = (data->size + 1023) / 1024;
	flash->chip->total_bytes = data->size;
	flash->chip->page_size = data->size;
	flash->chip->tested = (struct tested){ .probe = OK, .read = OK, .erase = NA, .write = NA, .wp = NA };
	flash->chip->gran = WRITE_GRAN_1BYTE_IMPLICIT_ERASE;
	flash->chip->block_erasers->eraseblocks[0].size = flash->chip->page_size;
	flash->chip->block_erasers->eraseblocks[0].count = 1;

	return 1;
}

static int anypci_read(struct flashctx *flash, uint8_t *buf, unsigned int start, unsigned int len)
{
	const struct anypci_data *data = flash->mst->opaque.data;

	len &= -data->width;
	while (len > 0) {
		if (data->bar == 0) {
			if (data->width == 1)
				*(uint8_t*)buf = pci_read_byte(data->dev, start);
			else if (data->width == 4)
				*(uint32_t*)buf = cpu_to_le32(pci_read_long(data->dev, start));
		}
		else if (data->bartype == TYPE_MEMBAR || data->bartype == TYPE_ROMBAR) {
			if (data->width == 1)
				*(uint8_t*)buf = pci_mmio_readb(data->virt_addr + start);
			else if (data->width == 4)
				*(uint32_t*)buf = cpu_to_le32(pci_mmio_readl(data->virt_addr + start));
		}
		else if (data->bartype == TYPE_IOBAR) {
#if __FLASHROM_HAVE_OUTB__
			if (data->width == 1)
				*(uint8_t*)buf = INB(data->phys_addr + start);
			else if (data->width == 4)
				*(uint32_t*)buf = cpu_to_le32(INL(data->phys_addr + start));
#endif
		}
		start += data->width;
		len -= data->width;
		buf += data->width;
	}
	return 0;
}

static int anypci_write(struct flashctx *flash, const uint8_t *buf, unsigned int start, unsigned int len)
{
	return 0;
}

static int anypci_erase(struct flashctx *flash, unsigned int blockaddr, unsigned int blocklen)
{
	return 0;
}

static int anypci_shutdown(void *par_data)
{
	const struct anypci_data *data = (struct anypci_data*)par_data;

	if (data->supported_cycles_before != data->supported_cycles_after)
		pci_write_word(data->dev, PCI_COMMAND, data->supported_cycles_before);
	if (data->bar_addr_before != data->bar_addr_after)
		pci_write_long(data->dev, data->bar, data->bar_addr_before);

	free(par_data);
	return 0;
}

static const struct opaque_master opaque_master_anypci = {
	.shutdown   = anypci_shutdown,
	.probe      = anypci_probe,
	.read       = anypci_read,
	.write      = anypci_write,
	.erase      = anypci_erase,
};

static int anypci_init(const struct programmer_cfg *cfg)
{
	struct pci_dev *dev = NULL;
	uintptr_t phys_addr = 0;
	uint8_t *virt_addr = NULL;
	int size = 0;
	int offset = 0;
	char *tmp;
	char *endptr;
	int bar;
	uint8_t headertype;

	dev = pcidev_init(cfg, anypci_devs, -1);
	if (!dev)
		return 1;

	headertype = pci_read_byte(dev, PCI_HEADER_TYPE) & 0x7f;
	switch (headertype) {
		case PCI_HEADER_TYPE_NORMAL: bar = PCI_ROM_ADDRESS; break;
		case PCI_HEADER_TYPE_BRIDGE: bar = PCI_ROM_ADDRESS1; break;
		case PCI_HEADER_TYPE_CARDBUS: bar = -1; break;
		default: msg_perr("Unknown PCI header type 0x%02x, BAR type cannot be determined reliably.\n", headertype); return 1;
	}

	endptr = NULL;
	tmp = extract_programmer_param_str(cfg, "bar");
	if (tmp)
		bar = (int)strtoul(tmp, &endptr, 0);
	if ((tmp && (!endptr || *endptr != '\0')) || bar < 0) {
		msg_perr("Invalid bar number. Specify the bar number like this: -p anypci:bar=0x30\n");
		free(tmp);
		return 1;
	}
	if (tmp)
		free(tmp);

	endptr = NULL;
	tmp = extract_programmer_param_str(cfg, "offset");
	if (tmp) {
		offset = (int)strtoul(tmp, &endptr, 0);
		if (!endptr || *endptr != '\0' || offset < 0) {
			msg_perr("Invalid offset. Specify the offset like this: -p anypci:offset=0\n");
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	endptr = NULL;
	tmp = extract_programmer_param_str(cfg, "size");
	if (tmp) {
		size = (int)strtoul(tmp, &endptr, 0);
		if (!endptr || *endptr != '\0' || size <= 0) {
			msg_perr("Invalid size. Specify the size like this: -p anypci:size=0x10000\n");
			free(tmp);
			return 1;
		}
		free(tmp);
	}

	struct anypci_data *data = calloc(1, sizeof(*data));
	if (!data) {
		msg_perr("Unable to allocate space for PAR master data\n");
		return 1;
	}
	bzero(data, sizeof(*data));
	data->dev = dev;
	data->bar = bar;
	data->width = 1;

	pci_bartype bartype; uint64_t barsize;
	uint16_t supported_cycles_before, supported_cycles_after;
	uint32_t bar_addr_before, bar_addr_after;

	if (bar) {
		phys_addr = pcidev_readbar_2(dev, bar, true, false, &bartype, &barsize,
			&supported_cycles_before, &supported_cycles_after,
			&bar_addr_before, &bar_addr_after
		);
		if (!phys_addr) {
			anypci_shutdown(data);
			return 1;
		}
		data->bartype = bartype;
		data->supported_cycles_before = supported_cycles_before;
		data->supported_cycles_after = supported_cycles_after;
		data->bar_addr_before = bar_addr_before;
		data->bar_addr_after = bar_addr_after;
	}
	else {
		barsize = 0x1000;
	}

	if (size == 0 && barsize <= 0xffffffff)
		size = (int)barsize - offset;
	if (size <= 0) {
		msg_perr("Invalid size. Specify the size like this: -p anypci:size=0x10000\n");
		free(tmp);
		anypci_shutdown(data);
		return 1;
	}
	data->size = size;

	phys_addr += offset;
	if (bar) {
		if (bartype == TYPE_MEMBAR || bartype == TYPE_ROMBAR) {
			virt_addr = physmap_ro("Any PCI Device memory region", phys_addr, size);
			if (virt_addr == ERROR_PTR) {
				anypci_shutdown(data);
				return 1;
			}
		}
		else if (bartype == TYPE_IOBAR) {
#if __FLASHROM_HAVE_OUTB__
			if (rget_io_perms()) {
				anypci_shutdown(data);
				return 1;
			}
#else
			msg_perr("I/O BAR access requested, but flashrom does not support I/O BAR access on this platform (yet).\n");
			anypci_shutdown(data);
			return 1;
#endif
		}
	}

	data->virt_addr = virt_addr;
	data->phys_addr = phys_addr;
	return register_opaque_master(&opaque_master_anypci, data);
}

const struct programmer_entry programmer_anypci = {
	.name			= "anypci",
	.type			= PCI,
	.devs.dev		= anypci_devs,
	.init			= anypci_init,
};
