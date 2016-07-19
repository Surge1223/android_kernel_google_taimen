/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DEBUG 1
#define DUMP_VERBOSITY 1 /* 1..4 */

#include <linux/kexec.h>
#include <linux/libfdt_env.h>
#include <linux/of_fdt.h>
#include <linux/smp.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/cpu_ops.h>
#include <asm/mmu_context.h>

#include "cpu-reset.h"

/* Bypass purgatory for debugging. */
static bool bypass_purgatory;
core_param(bypass_purgatory, bypass_purgatory, bool, 0644);

/* Global variables for the arm64_relocate_new_kernel routine. */
extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned long arm64_relocate_new_kernel_size;

static unsigned long kimage_start;

/**
 * kexec_is_kernel_header - Helper routine to check the kernel header signature.
 */
static bool kexec_is_kernel_header(const void *image)
{
	struct arm64_image_header {
		uint8_t pe_sig[2];
		uint16_t branch_code[3];
		uint64_t text_offset;
		uint64_t image_size;
		uint8_t flags[8];
		uint64_t reserved_1[3];
		uint8_t magic[4];
		uint32_t pe_header;
	} h;

        if (copy_from_user(&h, image, sizeof(struct arm64_image_header)))
		return false;

	if (!h.text_offset)
		return false;

	return (h.magic[0] == 'A'
		&& h.magic[1] == 'R'
		&& h.magic[2] == 'M'
		&& h.magic[3] == 0x64U);
}

/**
 * kexec_find_kernel - Helper routine to find the kernel entry.
 */
static unsigned long kexec_find_kernel(const struct kimage *kimage)
{
	int i;

	for (i = 0; i < kimage->nr_segments; i++) {
		unsigned long header_offset;

		for (header_offset = 0; header_offset < 2 * 1024 * 1024;
			header_offset += 4 * 1024) {
			if (!kexec_is_kernel_header(kimage->segment[i].buf +
				header_offset))
				continue;
			BUG_ON(!kimage->segment[i].mem);
			return kimage->segment[i].mem + header_offset;
		}
	}
	BUG();
	return 0;
}

/**
 * kexec_is_dtb - Helper routine to check the device tree header signature.
 */
static bool kexec_is_dtb(const void *dtb)
{
	__be32 magic;

	if (get_user(magic, (__be32 *)dtb))
		return false;

	return fdt32_to_cpu(magic) == OF_DT_HEADER;
}

/**
 * kexec_find_dtb - Helper routine to find the dtb.
 */
static unsigned long kexec_find_dtb(const struct kimage *kimage)
{
	int i;

	for (i = 0; i < kimage->nr_segments; i++) {
		if (kexec_is_dtb(kimage->segment[i].buf)) {
			BUG_ON(!kimage->segment[i].mem);
			return kimage->segment[i].mem;
		}
	}

	BUG();
	return 0;
}

static struct bypass {
	unsigned long kernel;
	unsigned long dtb;
} bypass;

static void fill_bypass(const struct kimage *kimage)
{
	bypass.kernel = kexec_find_kernel(kimage);
	bypass.dtb = kexec_find_dtb(kimage);

	pr_debug("%s: kernel: %016lx\n", __func__, bypass.kernel);
	pr_debug("%s: dtb:    %016lx\n", __func__, bypass.dtb);
}

/**
 * kexec_list_walk - Helper to walk the kimage page list.
 */
static void kexec_list_walk(void *ctx, struct kimage *kimage,
	void (*cb)(void *ctx, unsigned int flag, void *addr, void *dest))
{
	void *dest;
	kimage_entry_t *entry;

	for (entry = &kimage->head, dest = NULL; ; entry++) {
		unsigned int flag = *entry & IND_FLAGS;
		void *addr;

		if (flag == IND_DONE) {
			cb(ctx, flag , NULL, NULL);
			break;
		}

		addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			entry = (kimage_entry_t *)addr - 1;
			cb(ctx, flag, addr, NULL);
			break;
		case IND_DESTINATION:
			dest = addr;
			cb(ctx, flag, addr, NULL);
			break;
		case IND_SOURCE:
			cb(ctx, flag, addr, dest);
			dest += PAGE_SIZE;
			break;
		default:
			break;
		}
	}
}

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
	const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:%d:\n", func, line);
	pr_debug("  kexec kimage info:\n");
	pr_debug("    type:        %d\n", kimage->type);
	pr_debug("    start:       %lx\n", kimage->start);
	pr_debug("    head:        %lx\n", kimage->head);
	pr_debug("    nr_segments: %lu\n", kimage->nr_segments);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("      segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);
	}
}

/**
 * kexec_list_dump - Debugging dump of the kimage page list.
 */
static void kexec_list_dump_cb(void *ctx, unsigned int flag, void *addr,
	void *dest)
{
	unsigned int verbosity = (unsigned long)ctx;
	phys_addr_t paddr = virt_to_phys(addr);
	phys_addr_t pdest = virt_to_phys(dest);

	switch (flag) {
	case IND_INDIRECTION:
		pr_debug("  I: %pa (%p)\n", &paddr, addr);
		break;
	case IND_DESTINATION:
		pr_debug("  D: %pa (%p)\n",
			&paddr, addr);
		break;
	case IND_SOURCE:
		if (verbosity == 2)
			pr_debug("S");
		if (verbosity == 3)
			pr_debug("  S -> %pa (%p)\n", &pdest, dest);
		if (verbosity == 4)
			pr_debug("  S: %pa (%p) -> %pa (%p)\n", &paddr, addr,
				&pdest, dest);
		break;
	case IND_DONE:
		pr_debug("  DONE\n");
		break;
	default:
		pr_debug("  ?: %pa (%p)\n", &paddr, addr);
		break;
	}
}

#define kexec_list_dump(_i, _v) _kexec_list_dump(__func__, __LINE__, _i, _v)
static void _kexec_list_dump(const char *func, int line,
	struct kimage *kimage, unsigned int verbosity)
{
#if !defined(DEBUG)
	return;
#endif

	pr_debug("%s:%d: kexec_list_dump:\n", func, line);

	kexec_list_walk((void *)(unsigned long)verbosity, kimage,
		kexec_list_dump_cb);
}

static void dump_cpus(void)
{
	unsigned int cpu;
	char s[1024];
	char *p;

	p = s + sprintf(s, "%s: all:       ", __func__);
	for_each_cpu(cpu, cpu_all_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: possible:  ", __func__);
	for_each_possible_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: present:   ", __func__);
	for_each_present_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: active:    ", __func__);
	for_each_cpu(cpu, cpu_active_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: online:    ", __func__);
	for_each_online_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: not online:", __func__);
	for_each_cpu_not(cpu, cpu_online_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	/* Empty routine needed to avoid build errors. */
}

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 * Forbid loading a kexec kernel if we have no way of hotplugging cpus or cpus
 * are stuck in the kernel. This avoids a panic once we hit machine_kexec().
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	kimage_start = kimage->start;

	kexec_image_info(kimage);
	fill_bypass(kimage);

	if (kimage->type != KEXEC_TYPE_CRASH && cpus_are_stuck_in_kernel()) {
		pr_err("Can't kexec: CPUs are stuck in the kernel.\n");
		return -EBUSY;
	}

	return 0;
}

/**
 * kexec_list_flush - Helper to flush the kimage list and source pages to PoC.
 */
static void kexec_list_flush(struct kimage *kimage)
{
	kimage_entry_t *entry;

	for (entry = &kimage->head; ; entry++) {
		unsigned int flag;
		void *addr;

		/* flush the list entries. */
		__flush_dcache_area(entry, sizeof(kimage_entry_t));

		flag = *entry & IND_FLAGS;
		if (flag == IND_DONE)
			break;

		addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			/* Set entry point just before the new list page. */
			entry = (kimage_entry_t *)addr - 1;
			break;
		case IND_SOURCE:
			/* flush the source pages. */
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DESTINATION:
			break;
		default:
			BUG();
		}
	}
}

/**
 * kexec_segment_flush - Helper to flush the kimage segments to PoC.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:\n", __func__);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("  segment[%lu]: %016lx - %016lx, 0x%lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

		__flush_dcache_area(phys_to_virt(kimage->segment[i].mem),
			kimage->segment[i].memsz);
	}
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
	phys_addr_t reboot_code_buffer_phys;
	void *reboot_code_buffer;

	/*
	 * New cpus may have become stuck_in_kernel after we loaded the image.
	 */
	BUG_ON(cpus_are_stuck_in_kernel() || (num_online_cpus() > 1));

	reboot_code_buffer_phys = page_to_phys(kimage->control_code_page);
	reboot_code_buffer = phys_to_virt(reboot_code_buffer_phys);

	kexec_image_info(kimage);

	pr_debug("%s:%d: control_code_page:        %p\n", __func__, __LINE__,
		kimage->control_code_page);
	pr_debug("%s:%d: reboot_code_buffer_phys:  %pa\n", __func__, __LINE__,
		&reboot_code_buffer_phys);
	pr_debug("%s:%d: reboot_code_buffer:       %p\n", __func__, __LINE__,
		reboot_code_buffer);
	pr_debug("%s:%d: relocate_new_kernel:      %p\n", __func__, __LINE__,
		arm64_relocate_new_kernel);
	pr_debug("%s:%d: relocate_new_kernel_size: 0x%lx(%lu) bytes\n",
		__func__, __LINE__, arm64_relocate_new_kernel_size,
		arm64_relocate_new_kernel_size);

	kexec_list_dump(kimage, DUMP_VERBOSITY);
	dump_cpus();

	/*
	 * Copy arm64_relocate_new_kernel to the reboot_code_buffer for use
	 * after the kernel is shut down.
	 */
	memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
		arm64_relocate_new_kernel_size);

	/* Flush the reboot_code_buffer in preparation for its execution. */
	__flush_dcache_area(reboot_code_buffer, arm64_relocate_new_kernel_size);
	flush_icache_range((uintptr_t)reboot_code_buffer,
		arm64_relocate_new_kernel_size);

	/* Flush the kimage list and its buffers. */
	kexec_list_flush(kimage);

	/* Flush the new image if already in place. */
	if (kimage->head & IND_DONE)
		kexec_segment_flush(kimage);

	pr_info("Bye!\n");

	/* Disable all DAIF exceptions. */
	asm volatile ("msr daifset, #0xf" : : : "memory");

	/*
	 * cpu_soft_restart will shutdown the MMU, disable data caches, then
	 * transfer control to the reboot_code_buffer which contains a copy of
	 * the arm64_relocate_new_kernel routine.  arm64_relocate_new_kernel
	 * uses physical addressing to relocate the new image to its final
	 * position and transfers control to the image entry point when the
	 * relocation is complete.
	 */

	if (bypass_purgatory)
	cpu_soft_restart(1, reboot_code_buffer_phys, kimage->head,
		bypass.kernel, bypass.dtb);
	else
	cpu_soft_restart(1, reboot_code_buffer_phys, kimage->head,
		kimage_start, 0);

	BUG(); /* Should never get here. */
}

void machine_crash_shutdown(struct pt_regs *regs)
{
	/* Empty routine needed to avoid build errors. */
}
