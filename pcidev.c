/*
 * This file is part of the flashrom project.
 *
 * Copyright (C) 2009 Uwe Hermann <uwe@hermann-uwe.de>
 * Copyright (C) 2010, 2011 Carl-Daniel Hailfinger
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

#include <stdlib.h>
#include <string.h>
#include "flash.h"
#include "programmer.h"
#include "platform/pci.h"

struct pci_access *pacc;

uintptr_t pcidev_readbar_2(
	struct pci_dev *dev, int bar,
	bool enable_bar, bool get_size_unsafe,
	pci_bartype *pbartype, uint64_t *pbarsize,
	uint16_t *psupported_cycles_before, uint16_t *psupported_cycles_after,
	uint32_t *pbar_addr_before, uint32_t *pbar_addr_after
)
{
	pci_bartype bartype = TYPE_UNKNOWN;
	uint64_t barsize = 0;

	uint16_t supported_cycles = pci_read_word(dev, PCI_COMMAND);
	if (psupported_cycles_before) *psupported_cycles_before = supported_cycles;
	if (psupported_cycles_after) *psupported_cycles_after = supported_cycles;

	uint8_t headertype = pci_read_byte(dev, PCI_HEADER_TYPE) & 0x7f;
	msg_pspew("PCI header type 0x%02x\n", headertype);

	/* Don't use dev->base_addr[x] (as value for 'bar'), won't work on older libpci. */
	uint32_t upperaddr = 0;
	uint32_t loweraddr = pci_read_long(dev, bar);
	if (pbar_addr_before) *pbar_addr_before = loweraddr;
	if (pbar_addr_after) *pbar_addr_after = loweraddr;
	uint64_t fulladdr = loweraddr;

	/* Sanity checks. */
	switch (headertype) {
	case PCI_HEADER_TYPE_NORMAL:
		switch (bar) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
		case PCI_BASE_ADDRESS_2:
		case PCI_BASE_ADDRESS_3:
		case PCI_BASE_ADDRESS_4:
		case PCI_BASE_ADDRESS_5:
			if ((loweraddr & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO)
				bartype = TYPE_IOBAR;
			else
				bartype = TYPE_MEMBAR;
			break;
		case PCI_ROM_ADDRESS:
			bartype = TYPE_ROMBAR;
			break;
		}
		break;
	case PCI_HEADER_TYPE_BRIDGE:
		switch (bar) {
		case PCI_BASE_ADDRESS_0:
		case PCI_BASE_ADDRESS_1:
			if ((loweraddr & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO)
				bartype = TYPE_IOBAR;
			else
				bartype = TYPE_MEMBAR;
			break;
		case PCI_ROM_ADDRESS1:
			bartype = TYPE_ROMBAR;
			break;
		}
		break;
	case PCI_HEADER_TYPE_CARDBUS:
		break;
	default:
		msg_perr("Unknown PCI header type 0x%02x, BAR type cannot be determined reliably.\n",
			 headertype);
		break;
	}

	msg_pdbg("Requested BAR 0x%02x is of type ", bar);
	switch (bartype) {
	case TYPE_MEMBAR:
		msg_pdbg("MEM, %sbit, %sprefetchable\n",
			 ((loweraddr & 0x6) == 0x0) ? "32" : (((loweraddr & 0x6) == 0x4) ? "64" : "reserved"),
			 (loweraddr & 0x8) ? "" : "not ");
		if ((loweraddr & 0x6) == 0x4) {
			/* The spec says that a 64-bit register consumes
			 * two subsequent dword locations.
			 */
			upperaddr = pci_read_long(dev, bar + 4);
			if (upperaddr != 0x00000000) {
				/* Fun! A real 64-bit resource. */
				if (sizeof(uintptr_t) != sizeof(uint64_t)) {
					msg_perr("BAR unreachable!");
					fulladdr = 0;
					break;
				}
				fulladdr |= (uint64_t)upperaddr << 32;
			}
		}
		fulladdr &= PCI_BASE_ADDRESS_MEM_MASK;

		if (!(supported_cycles & PCI_COMMAND_MEMORY) || get_size_unsafe) {
			pci_write_long(dev, bar, 0xffffffff & PCI_BASE_ADDRESS_MEM_MASK);
			uint32_t lowersize = pci_read_long(dev, bar);
			pci_write_long(dev, bar, loweraddr);
			barsize = lowersize & PCI_BASE_ADDRESS_MEM_MASK;
			if ((loweraddr & 0x6) == 0x4) {
				pci_write_long(dev, bar+4, 0xffffffff);
				uint32_t uppersize = pci_read_long(dev, bar);
				pci_write_long(dev, bar+4, upperaddr);
				barsize |= (uint64_t)uppersize << 32;
			}
		}

		if (!(supported_cycles & PCI_COMMAND_MEMORY)) {
			if (enable_bar) {
				pci_write_long(dev, PCI_COMMAND, supported_cycles | PCI_COMMAND_MEMORY);
				if (psupported_cycles_after) *psupported_cycles_after = supported_cycles | PCI_COMMAND_MEMORY;
			}
			else {
				msg_perr("MEM BAR access requested, but device has MEM space accesses disabled.\n");
				/* TODO: Abort here? */
			}
		}
		break;
	case TYPE_IOBAR:
		msg_pdbg("I/O\n");
		fulladdr &= PCI_BASE_ADDRESS_IO_MASK;
#if __FLASHROM_HAVE_OUTB__
		if (!(supported_cycles & PCI_COMMAND_IO) || get_size_unsafe) {
			pci_write_long(dev, bar, 0xffffffff & PCI_BASE_ADDRESS_IO_MASK);
			uint32_t lowersize = pci_read_long(dev, bar);
			pci_write_long(dev, bar, loweraddr);
			barsize = lowersize & PCI_BASE_ADDRESS_IO_MASK;
		}

		if (!(supported_cycles & PCI_COMMAND_IO)) {
			if (enable_bar) {
				pci_write_long(dev, PCI_COMMAND, supported_cycles | PCI_COMMAND_IO);
				if (psupported_cycles_after) *psupported_cycles_after = supported_cycles | PCI_COMMAND_IO;
			}
			else {
				msg_perr("I/O BAR access requested, but device has I/O space accesses disabled.\n");
				/* TODO: Abort here? */
			}
		}
#else
		msg_perr("I/O BAR access requested, but flashrom does not support I/O BAR access on this platform (yet).\n");
#endif
		break;
	case TYPE_ROMBAR:
		msg_pdbg("ROM\n");
		fulladdr &= PCI_ROM_ADDRESS_MASK;

		if (!(supported_cycles & PCI_COMMAND_MEMORY) || !(loweraddr & PCI_ROM_ADDRESS_ENABLE) || get_size_unsafe) {
			pci_write_long(dev, bar, 0xffffffff & PCI_ROM_ADDRESS_MASK);
			uint32_t lowersize = pci_read_long(dev, bar);
			pci_write_long(dev, bar, loweraddr);
			barsize = lowersize & PCI_ROM_ADDRESS_MASK;
		}

		if (!(supported_cycles & PCI_COMMAND_MEMORY)) {
			if (enable_bar) {
				pci_write_long(dev, PCI_COMMAND, supported_cycles | PCI_COMMAND_MEMORY);
				if (psupported_cycles_after) *psupported_cycles_after = supported_cycles | PCI_COMMAND_MEMORY;
			}
			else {
				msg_perr("ROM BAR access requested, but device has MEM space accesses disabled.\n");
				/* TODO: Abort here? */
			}
		}
		if (!(loweraddr & PCI_ROM_ADDRESS_ENABLE)) {
			if (enable_bar) {
				pci_write_long(dev, bar, loweraddr | PCI_ROM_ADDRESS_ENABLE);
				if (pbar_addr_after) *pbar_addr_after = loweraddr | PCI_ROM_ADDRESS_ENABLE;
			}
			else {
				msg_perr("ROM BAR access requested, but ROM access is disabled.\n");
				/* TODO: Abort here? */
			}
		}
		break;
	case TYPE_UNKNOWN:
		msg_perr("BAR type unknown, please report a bug at flashrom@flashrom.org\n");
	}

	if (barsize) {
		int i;
		for (i = 63; i >= 0 && !(barsize & (1ULL << i)); i--)
			barsize |= (1ULL << i);
		barsize = -barsize;
		msg_pdbg("%d bit BAR has size %lld %s\n", i + 1,
			(barsize & 1023) ? barsize : barsize / 1024,
			(barsize & 1023) ? "bytes" : "kB"
		);
	}

	if (pbartype) *pbartype = bartype;
	if (pbarsize) *pbarsize = barsize;
	return (uintptr_t)fulladdr;
}

uintptr_t pcidev_readbar(struct pci_dev *dev, int bar)
{
	return pcidev_readbar_2(dev, bar, false, false, NULL, NULL, NULL, NULL, NULL, NULL);
}

struct pci_dev *pcidev_scandev(struct pci_filter *filter, struct pci_dev *start)
{
	struct pci_dev *temp;
	for (temp = start ? start->next : pacc->devices; temp; temp = temp->next) {
		if (pci_filter_match(filter, temp)) {
			pci_fill_info(temp, PCI_FILL_IDENT);
			return temp;
		}
	}
	return NULL;
}

struct pci_dev *pcidev_card_find(uint16_t vendor, uint16_t device,
				 uint16_t card_vendor, uint16_t card_device)
{
	struct pci_dev *temp = NULL;
	struct pci_filter filter;

	pci_filter_init(NULL, &filter);
	filter.vendor = vendor;
	filter.device = device;

	while ((temp = pcidev_scandev(&filter, temp))) {
		if (
			(card_vendor == pci_read_word(temp, PCI_SUBSYSTEM_VENDOR_ID)) &&
			(card_device == pci_read_word(temp, PCI_SUBSYSTEM_ID))
		)
			return temp;
	}

	return NULL;
}

struct pci_dev *pcidev_find(uint16_t vendor, uint16_t device)
{
	struct pci_filter filter;

	pci_filter_init(NULL, &filter);
	filter.vendor = vendor;
	filter.device = device;

	return pcidev_scandev(&filter, NULL);
}

struct pci_dev *pcidev_getdevfn(struct pci_dev *dev, const int func)
{
	struct pci_dev *const new = pci_get_dev(pacc, dev->domain, dev->bus, dev->dev, func);
	if (new)
		pci_fill_info(new, PCI_FILL_IDENT);
	return new;
}

struct pci_dev *pcidev_find_vendorclass(uint16_t vendor, uint16_t devclass)
{
	struct pci_dev *temp = NULL;
	struct pci_filter filter;
	uint16_t tmp2;

	pci_filter_init(NULL, &filter);
	filter.vendor = vendor;

	while ((temp = pcidev_scandev(&filter, temp))) {
		/* Read PCI class */
		tmp2 = pci_read_word(temp, PCI_CLASS_DEVICE);
		if (tmp2 == devclass)
			return temp;
	}

	return NULL;
}

static int pcidev_shutdown(void *data)
{
	if (pacc == NULL) {
		msg_perr("%s: Tried to cleanup an invalid PCI context!\n"
			 "Please report a bug at flashrom@flashrom.org\n", __func__);
		return 1;
	}
	pci_cleanup(pacc);
	pacc = NULL;
	return 0;
}

int pci_init_common(void)
{
	if (pacc != NULL) {
		msg_perr("%s: Tried to allocate a new PCI context, but there is still an old one!\n"
			 "Please report a bug at flashrom@flashrom.org\n", __func__);
		return 1;
	}
	pacc = pci_alloc();     /* Get the pci_access structure */
	pci_init(pacc);         /* Initialize the PCI library */
	if (register_shutdown(pcidev_shutdown, NULL))
		return 1;
	pci_scan_bus(pacc);     /* We want to get the list of devices */
	return 0;
}

/* pcidev_init gets an array of allowed PCI device IDs and returns a pointer to struct pci_dev iff exactly one
 * match was found. If the "pci=bb:dd.f" programmer parameter was specified, a match is only considered if it
 * also matches the specified bus:device.function.
 * For convenience, this function also registers its own undo handlers.
 */
struct pci_dev *pcidev_init(const struct programmer_cfg *cfg, const struct dev_entry *devs, int bar)
{
	struct pci_dev *dev;
	struct pci_dev *found_dev = NULL;
	struct pci_filter filter;
	char *pcidev_bdf;
	char *msg = NULL;
	int found = 0;
	int i;

	if (pci_init_common() != 0)
		return NULL;
	pci_filter_init(pacc, &filter);

	/* Filter by bb:dd.f (if supplied by the user). */
	pcidev_bdf = extract_programmer_param_str(cfg, "pci");
	if (pcidev_bdf != NULL) {
		if ((msg = pci_filter_parse_slot(&filter, pcidev_bdf))) {
			msg_perr("Error: %s\n", msg);
			return NULL;
		}
	}
	free(pcidev_bdf);

	for (dev = pacc->devices; dev; dev = dev->next) {
		if (pci_filter_match(&filter, dev)) {
			pci_fill_info(dev, PCI_FILL_IDENT);
			/* Check against list of supported devices. */
			for (i = 0; devs[i].device_name != NULL; i++)
				if (
					(devs[i].vendor_id == 0xffff || dev->vendor_id == devs[i].vendor_id) &&
					(devs[i].device_id == 0xffff || dev->device_id == devs[i].device_id)
				)
					break;
			/* Not supported, try the next one. */
			if (devs[i].device_name == NULL)
				continue;

			msg_pinfo("Found \"%s %s\" (%04x:%04x, BDF %02x:%02x.%x).\n", devs[i].vendor_name,
				 devs[i].device_name, dev->vendor_id, dev->device_id, dev->bus, dev->dev,
				 dev->func);
			if (devs[i].status == NT)
				msg_pinfo("===\nThis PCI device is UNTESTED. Please report the 'flashrom -p "
					  "xxxx' output\n"
					  "to flashrom@flashrom.org if it works for you. Please add the name "
					  "of your\n"
					  "PCI device to the subject. Thank you for your help!\n===\n");

			/* FIXME: We should count all matching devices, not
			 * just those with a valid BAR.
			 */
			if (bar == -1 || pcidev_readbar(dev, bar) != 0) {
				found_dev = dev;
				found++;
			}
		}
	}

	/* Only continue if exactly one supported PCI dev has been found. */
	if (found == 0) {
		msg_perr("Error: No supported PCI device found.\n");
		return NULL;
	} else if (found > 1) {
		msg_perr("Error: Multiple supported PCI devices found. Use 'flashrom -p xxxx:pci=bb:dd.f'\n"
			 "to explicitly select the card with the given BDF (PCI bus, device, function).\n");
		return NULL;
	}

	return found_dev;
}

enum pci_write_type {
	pci_write_type_byte,
	pci_write_type_word,
	pci_write_type_long,
};

struct undo_pci_write_data {
	struct pci_dev *dev;
	int reg;
	enum pci_write_type type;
	union {
		uint8_t bytedata;
		uint16_t worddata;
		uint32_t longdata;
	};
};

static int undo_pci_write(void *p)
{
	struct undo_pci_write_data *data = p;
	if (pacc == NULL || data->dev == NULL) {
		msg_perr("%s: Tried to undo PCI writes without a valid PCI %s!\n"
			"Please report a bug at flashrom@flashrom.org\n",
			__func__, data->dev == NULL ? "device" : "context");
		return 1;
	}
	msg_pdbg("Restoring PCI config space for %02x:%02x:%01x reg 0x%02x\n",
		 data->dev->bus, data->dev->dev, data->dev->func, data->reg);
	switch (data->type) {
	case pci_write_type_byte:
		pci_write_byte(data->dev, data->reg, data->bytedata);
		break;
	case pci_write_type_word:
		pci_write_word(data->dev, data->reg, data->worddata);
		break;
	case pci_write_type_long:
		pci_write_long(data->dev, data->reg, data->longdata);
		break;
	}
	/* p was allocated in register_undo_pci_write. */
	free(p);
	return 0;
}

#define register_undo_pci_write(a, b, c)				\
{									\
	struct undo_pci_write_data *undo_pci_write_data;		\
	undo_pci_write_data = malloc(sizeof(*undo_pci_write_data));	\
	if (!undo_pci_write_data) {					\
		msg_gerr("Out of memory!\n");				\
		exit(1);						\
	}								\
	if (pacc)							\
		undo_pci_write_data->dev = pci_get_dev(pacc,		\
				a->domain, a->bus, a->dev, a->func);	\
	else								\
		undo_pci_write_data->dev =  NULL;			\
	undo_pci_write_data->reg = b;					\
	undo_pci_write_data->type = pci_write_type_##c;			\
	undo_pci_write_data->c##data = pci_read_##c(dev, reg);		\
	register_shutdown(undo_pci_write, undo_pci_write_data);		\
}

#define register_undo_pci_write_byte(a, b) register_undo_pci_write(a, b, byte)
#define register_undo_pci_write_word(a, b) register_undo_pci_write(a, b, word)
#define register_undo_pci_write_long(a, b) register_undo_pci_write(a, b, long)

int rpci_write_byte(struct pci_dev *dev, int reg, uint8_t data)
{
	register_undo_pci_write_byte(dev, reg);
	return pci_write_byte(dev, reg, data);
}

int rpci_write_word(struct pci_dev *dev, int reg, uint16_t data)
{
	register_undo_pci_write_word(dev, reg);
	return pci_write_word(dev, reg, data);
}

int rpci_write_long(struct pci_dev *dev, int reg, uint32_t data)
{
	register_undo_pci_write_long(dev, reg);
	return pci_write_long(dev, reg, data);
}
