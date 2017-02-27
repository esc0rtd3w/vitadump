#include <stdio.h>
#include <string.h>
#include <taihen.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/io/fcntl.h>
#include "elf.h"

#define DUMP_PATH "ux0:dump/"
#define LOG_FILE DUMP_PATH "kplugin_log.txt"

static void log_write(const char *buffer, size_t length);

#define LOG(...) \
	do { \
		char buffer[256]; \
		snprintf(buffer, sizeof(buffer), ##__VA_ARGS__); \
		log_write(buffer, strlen(buffer)); \
	} while (0)

//user     1 -> usermodule
//fakecode 0 -> correct location
//usecdram 1 -> more ram
		
int decrypt_self(const char *path, const char *outprefix, int fakecode, int usecdram, int user)
{
    char outpath[256];
    int ctx;
    int ret;
    SceUID fd = 0, wfd = 0;
    char *somebuf = NULL;
    char *hdr_buf = NULL, *hdr_buf_aligned;
    char *data_buf = NULL, *data_buf_aligned;

    unsigned int hdr_size;

    // set up SBL decrypt context
    ret = SceSblAuthMgrForKernel_0xA9CD2A09(&ctx);
    LOG("SceSblAuthMgrForKernel_0xA9CD2A09: 0x%08X, CTX: 0x%08X\n", ret, ctx);
    if (ret < 0)
        return 1;

    // set up this weird buffer
	// comment here because it's causing shit
    somebuf = SceSysmemForKernel_0xC0A4D2F3(0x130);
    LOG("Weird buffer: 0x%08X\n", somebuf);
    if (somebuf == NULL)
        goto fail;
    memset(somebuf, 0, 0x130);
    if (ret < 0)
        goto fail;
	
    *(int *)(somebuf + 0x4) = user;
    *(uint64_t *)(somebuf + 0x8) = 0x2808000000000001LL;
    *(uint64_t *)(somebuf + 0x10) = 0xF000C000000080LL;
    *(uint64_t *)(somebuf + 0x18) = 0xFFFFFFFF00000000LL;
    *(uint64_t *)(somebuf + 0x30) = 0xC300003800980LL;
    *(uint64_t *)(somebuf + 0x38) = 0x8009800000LL;
    *(uint64_t *)(somebuf + 0x48) = 0xFFFFFFFF00000000LL;

    if (fakecode)
    {
        *(int *)(somebuf + 0x128) = fakecode;
    }
    else
    {
        ret = SceIofilemgrForDriver_0x9C220246(0x10005, path, 1, somebuf + 0x128);
        LOG("SceIofilemgrForDriver_0x9C220246: 0x%08X\n", ret);
        if (ret < 0)
            goto fail;
    }

    // read header
    fd = ksceIoOpen(path, 1, 0);
    LOG("ksceIoOpen: 0x%08X\n", fd);
    if (fd < 0)
        goto fail;
    hdr_buf = SceSysmemForKernel_0xC0A4D2F3(0x1000+63);
    hdr_buf_aligned = (char *)(((int)hdr_buf + 63) & 0xFFFFFFC0);
    LOG("Header buffer: 0x%08X, aligned: 0x%08X\n", hdr_buf, hdr_buf_aligned);
    if (hdr_buf == NULL)
        goto fail;
    ret = ksceIoRead(fd, hdr_buf_aligned, 0x1000);
    LOG("Header read: 0x%08X\n", ret);
    hdr_size = *(unsigned int *)(hdr_buf_aligned + 0x10);
    if (hdr_size > 0x1000)
    {
        LOG("Header too large: 0x%08X\n", hdr_size);
        goto fail;
    }
    ret = ksceIoLseek(fd, 0LL, 0);
    LOG("Header rewind: 0x%08X\n", ret);

    // set up SBL decryption for this SELF
    ret = SceSblAuthMgrForKernel_0xF3411881(ctx, hdr_buf_aligned, hdr_size, somebuf);
    LOG("SceSblAuthMgrForKernel_0xF3411881: 0x%08X\n", ret);
    if (ret < 0)
    {
        goto fail;
    }

    // set up read buffer
    data_buf = SceSysmemForKernel_0xC0A4D2F3(0x10000+63);
    data_buf_aligned = (char *)(((int)data_buf + 63) & 0xFFFFFFC0);
    LOG("Data buffer: 0x%08X, aligned: 0x%08X\n", data_buf, data_buf_aligned);
    if (data_buf == NULL)
        goto fail;

    // get sections
    int elf_offset = *(int*)(hdr_buf_aligned + 0x40);
    int num_segs = *(short*)(hdr_buf_aligned + elf_offset + 0x2C);
    LOG("Number of segments to read: 0x%04X\n", num_segs);
    int info_offset = *(int*)(hdr_buf_aligned + 0x58);
    seg_info *segs = (seg_info *)(hdr_buf_aligned + info_offset);
    int phdr_offset = *(int*)(hdr_buf_aligned + 0x48);
    Elf32_Phdr *phdrs = (Elf32_Phdr *)(hdr_buf_aligned + phdr_offset);

    // decrypt sections
    int i;
    int total, to_read, num_read, off;
    int aligned_size;
    int blkid = 0;
    void *pgr_buf;
    for (i = 0; i < num_segs; i++)
    {
        sprintf(outpath, "%s.seg%u", outprefix, i);
        ksceIoClose(wfd);
        wfd = ksceIoOpen(outpath, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 6);
        LOG("ksceIoOpen(%s): 0x%08X\n", outpath, wfd);
        if (wfd < 0)
            break;

        if (blkid)
            ksceKernelFreeMemBlock(blkid);
        aligned_size = (phdrs[i].p_filesz + 4095) & 0xFFFFF000;
        if (usecdram)
            blkid = ksceKernelAllocMemBlock("self_decrypt_buffer", 0x40404006, 0x4000000, NULL);
        else
            blkid = ksceKernelAllocMemBlock("self_decrypt_buffer", 0x1020D006, aligned_size, NULL);
        LOG("ksceKernelAllocMemBlock: 0x%08X, size: 0x%08X\n", blkid, aligned_size);
        ret = ksceKernelGetMemBlockBase(blkid, &pgr_buf);
        LOG("ksceKernelGetMemBlockBase: 0x%08X, base: 0x%08X\n", ret, pgr_buf);
        if (ret < 0)
            break;

        // setup buffer for output
        ret = SceSblAuthMgrForKernel_0x89CCDA2C(ctx, i, (uint32_t)segs[i].length, pgr_buf, phdrs[i].p_filesz);
        LOG("SceSblAuthMgrForKernel_0x89CCDA2C: 0x%08X\n", ret);
        if (ret < 0)
        {
            break;
        }

        ret = ksceIoLseek(fd, segs[i].offset, 0);
        LOG("ksceIoLseek(0x%08X): 0x%08X\n", (uint32_t)segs[i].offset, ret);
        if (ret < 0)
            break;
        total = (uint32_t)segs[i].length;
        to_read = total > 0x10000 ? 0x10000 : total;
        off = 0;
        while (total > 0 && (num_read = ksceIoRead(fd, data_buf_aligned+off, to_read)) > 0)
        {
            off += num_read;
            total -= num_read;
            if (num_read < to_read)
            {
                to_read -= num_read;
                continue;
            }

            ret = SceSblAuthMgrForKernel_0xBC422443(ctx, data_buf_aligned, off); // decrypt buffer
            LOG("SceSblAuthMgrForKernel_0xBC422443: 0x%08X\n", ret);
            if (ret < 0){
				LOG("!!! ERROR !!!\n");
			}
			ksceIoWrite(wfd, data_buf_aligned, to_read);
            //ret = memcpy(ctx, data_buf_aligned, off); // copy buffer to output
            /*LOG("memcpy: 0x%08X\n", ret);
            if (ret < 0)
            {
                LOG("!!! ERROR !!!\n");
            }
			*/
            off = 0;
            to_read = total > 0x10000 ? 0x10000 : total;
			
        }

        // write buffer
        off = 0;
        while ((off += ksceIoWrite(wfd, pgr_buf+off, phdrs[i].p_filesz-off)) < phdrs[i].p_filesz);
		
    }
    if (blkid)
        ksceKernelFreeMemBlock(blkid);
    ksceIoClose(wfd);

fail:
    SceSblAuthMgrForKernel_0x026ACBAD(ctx);
    if (fd)
        ksceIoClose(fd);
    if (somebuf)
        SceSysmemForKernel_0xABAB0FAB(somebuf);
    if (hdr_buf)
        SceSysmemForKernel_0xABAB0FAB(hdr_buf);
    if (data_buf)
        SceSysmemForKernel_0xABAB0FAB(data_buf);
    return 1;
}

void _start() __attribute__ ((weak, alias ("module_start")));

#define MOD_LIST_SIZE 0x80


void doDump(const SceKernelModuleInfo *info) {
	char path[128] = {0};
	int i;
	SceUID fd;
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;
	Elf32_Off offset;

	snprintf(path, sizeof(path), DUMP_PATH "%s.elf",
			info->module_name);

	LOG("Dumping %s\n", path);

	fd = ksceIoOpen(path, SCE_O_CREAT | SCE_O_WRONLY | SCE_O_TRUNC, 6);
	if (fd < 0) {
		LOG("Failed to open the file for writing.\n");
		return;
	}

	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELFCLASS32;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_ARM_AEABI;
	ehdr.e_ident[EI_ABIVERSION] = 0;
	memset(ehdr.e_ident + EI_PAD, 0, EI_NIDENT - EI_PAD);
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_ARM;
	ehdr.e_version = EV_CURRENT;
	ehdr.e_entry = (Elf32_Addr)info->module_start;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = EF_ARM_HASENTRY
					| EF_ARM_ABI_FLOAT_HARD
					| EF_ARM_EABI_VER5;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf32_Phdr);
	ehdr.e_shentsize = sizeof(Elf32_Shdr);
	ehdr.e_shnum = 0;
	ehdr.e_shstrndx = 0;

	ehdr.e_shoff = 0;
	ehdr.e_phnum = 0;
	for (i = 0; i < 4; ++i) {
		if (info->segments[i].vaddr == NULL)
			continue;

		++ehdr.e_phnum;
	}

	ksceIoWrite(fd, &ehdr, sizeof(ehdr));

	offset = sizeof(ehdr) + ehdr.e_phnum * sizeof(phdr);
	phdr.p_type = PT_LOAD;
	phdr.p_paddr = 0;
	phdr.p_align = 1;
	for (i = 0; i < 4; ++i) {
		if (info->segments[i].vaddr == NULL)
			continue;

		phdr.p_flags = info->segments[i].perms;
		phdr.p_offset = offset;
		phdr.p_vaddr = (Elf32_Addr)info->segments[i].vaddr;
		phdr.p_memsz = info->segments[i].memsz;
		phdr.p_filesz = phdr.p_memsz;

		ksceIoWrite(fd, &phdr, sizeof(phdr));

		offset += phdr.p_filesz;
	}

	for (i = 0; i < 4; ++i) {
		if (info->segments[i].vaddr == NULL) {
			LOG("Segment #%x is empty, skipping\n", i);
			continue;
		}

		ksceIoWrite(fd, info->segments[i].vaddr, info->segments[i].memsz);
	}

	ksceIoClose(fd);

	snprintf(path, sizeof(path), DUMP_PATH "%s_info.bin",
		 info->module_name);

	LOG("Dumping %s\n", path);

	fd = ksceIoOpen(path, SCE_O_CREAT | SCE_O_WRONLY | SCE_O_TRUNC, 6);
	if (fd < 0) {
		LOG("Failed to open the file for writing.\n");
		return;
	}

	ksceIoWrite(fd, info, sizeof(*info));
	ksceIoClose(fd);
}


int module_start(SceSize argc, const void *args)
{
	
	decrypt_self("ux0:tai/pcbc.skprx", "ux0:dump/pcbc_out.bin", 2, 1, 0); 
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	return SCE_KERNEL_STOP_SUCCESS;
}

void log_write(const char *buffer, size_t length)
{
	extern int ksceIoMkdir(const char *, int);
	ksceIoMkdir(DUMP_PATH, 6);

	SceUID fd = ksceIoOpen(LOG_FILE,
		SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 6);
	if (fd < 0)
		return;

	ksceIoWrite(fd, buffer, length);
	ksceIoClose(fd);
}
