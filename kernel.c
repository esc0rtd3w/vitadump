#include <stdio.h>
#include <string.h>
#include <unistd.h>
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
        snprintf(outpath, sizeof(outpath), "%s.seg%u", outprefix, i);
        ksceIoClose(wfd);
        wfd = ksceIoOpen(outpath, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 6);
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

int module_start(SceSize argc, const void *args)
{
	ksceIoRemove("ux0:dump/kplugin_log.txt");
	ksceIoRmdir("ux0:dump/out");
	ksceIoMkdir("ux0:dump/out", 6);
	ksceIoMkdir("ux0:dump/out/os0-", 6);
	ksceIoMkdir("ux0:dump/out/vs0-", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/app", 6);
	ksceIoMkdir("ux0:dump/out/os0-/kd", 6);
	ksceIoMkdir("ux0:dump/out/os0-/ue", 6);
	ksceIoMkdir("ux0:dump/out/os0-/us", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/data", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/sys", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/vsh", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/vsh/common", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/vsh/shell", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/sys/external", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/data/external", 6);
	ksceIoMkdir("ux0:dump/out/vs0-/data/external/webcore", 6);
	
	//Operating System modules and pspemu ipl
	
	decrypt_self("os0:kd/acmgr.skprx", "ux0:dump/out/os0-/kd/acmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/authmgr.skprx", "ux0:dump/out/os0-/kd/authmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/bootimage.skprx", "ux0:dump/out/os0-/kd/bootimage.skprx", 0, 1, 0);
	decrypt_self("os0:kd/bsod.skprx", "ux0:dump/out/os0-/kd/bsod.skprx", 0, 1, 0);
	decrypt_self("os0:kd/buserror.skprx", "ux0:dump/out/os0-/kd/buserror.skprx", 0, 1, 0);
	decrypt_self("os0:kd/crashdump.skprx", "ux0:dump/out/os0-/kd/crashdump.skprx", 0, 1, 0);
	decrypt_self("os0:kd/dbgsdio.skprx", "ux0:dump/out/os0-/kd/dbgsdio.skprx", 0, 1, 0);
	decrypt_self("os0:kd/dbgusb.skprx", "ux0:dump/out/os0-/kd/dbgusb.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_cpup.skprx", "ux0:dump/out/os0-/kd/deci4p_cpup.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_ctrlp.skprx", "ux0:dump/out/os0-/kd/deci4p_ctrlp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_dbgp.skprx", "ux0:dump/out/os0-/kd/deci4p_dbgp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_dfmgr.skprx", "ux0:dump/out/os0-/kd/deci4p_dfmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_drfp.skprx", "ux0:dump/out/os0-/kd/deci4p_drfp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_dtracep.skprx", "ux0:dump/out/os0-/kd/deci4p_dtracep.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_loadp.skprx", "ux0:dump/out/os0-/kd/deci4p_loadp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_pamp.skprx", "ux0:dump/out/os0-/kd/deci4p_pamp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_rdrfp.skprx", "ux0:dump/out/os0-/kd/deci4p_rdrfp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_scttyp.skprx", "ux0:dump/out/os0-/kd/deci4p_scttyp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sdbgp.skprx", "ux0:dump/out/os0-/kd/deci4p_sdbgp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sdeci2p.skprx", "ux0:dump/out/os0-/kd/deci4p_sdeci2p.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sdfctl.skprx", "ux0:dump/out/os0-/kd/deci4p_sdfctl.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sdfmgr.skprx", "ux0:dump/out/os0-/kd/deci4p_sdfmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sdrfp.skprx", "ux0:dump/out/os0-/kd/deci4p_sdrfp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_sttyp.skprx", "ux0:dump/out/os0-/kd/deci4p_sttyp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_tmcp.skprx", "ux0:dump/out/os0-/kd/deci4p_tmcp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_tsmp.skprx", "ux0:dump/out/os0-/kd/deci4p_tsmp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_ttyp.skprx", "ux0:dump/out/os0-/kd/deci4p_ttyp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_userp.skprx", "ux0:dump/out/os0-/kd/deci4p_userp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/deci4p_vcp.skprx", "ux0:dump/out/os0-/kd/deci4p_vcp.skprx", 0, 1, 0);
	decrypt_self("os0:kd/display.skprx", "ux0:dump/out/os0-/kd/display.skprx", 0, 1, 0);
	decrypt_self("os0:kd/dmacmgr.skprx", "ux0:dump/out/os0-/kd/dmacmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/enum_wakeup.skprx", "ux0:dump/out/os0-/kd/enum_wakeup.skprx", 0, 1, 0);
	decrypt_self("os0:kd/excpmgr.skprx", "ux0:dump/out/os0-/kd/excpmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/exfatfs.skprx", "ux0:dump/out/os0-/kd/exfatfs.skprx", 0, 1, 0);
	decrypt_self("os0:kd/gcauthmgr.skprx", "ux0:dump/out/os0-/kd/gcauthmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/gpucoredump_es4.skprx", "ux0:dump/out/os0-/kd/gpucoredump_es4.skprx", 0, 1, 0);
	decrypt_self("os0:kd/hdmi.skprx", "ux0:dump/out/os0-/kd/hdmi.skprx", 0, 1, 0);
	decrypt_self("os0:kd/intrmgr.skprx", "ux0:dump/out/os0-/kd/intrmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/iofilemgr.skprx", "ux0:dump/out/os0-/kd/iofilemgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/krm.skprx", "ux0:dump/out/os0-/kd/krm.skprx", 0, 1, 0);
	decrypt_self("os0:kd/lcd.skprx", "ux0:dump/out/os0-/kd/lcd.skprx", 0, 1, 0);
	decrypt_self("os0:kd/lowio.skprx", "ux0:dump/out/os0-/kd/lowio.skprx", 0, 1, 0);
	decrypt_self("os0:kd/magicgate.skprx", "ux0:dump/out/os0-/kd/magicgate.skprx", 0, 1, 0);
	decrypt_self("os0:kd/marlin_hci.skprx", "ux0:dump/out/os0-/kd/marlin_hci.skprx", 0, 1, 0);
	decrypt_self("os0:kd/mgkeymgr.skprx", "ux0:dump/out/os0-/kd/mgkeymgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/mgvideo.skprx", "ux0:dump/out/os0-/kd/mgvideo.skprx", 0, 1, 0);
	decrypt_self("os0:kd/modulemgr.skprx", "ux0:dump/out/os0-/kd/modulemgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/msif.skprx", "ux0:dump/out/os0-/kd/msif.skprx", 0, 1, 0);
	decrypt_self("os0:kd/oled.skprx", "ux0:dump/out/os0-/kd/oled.skprx", 0, 1, 0);
	decrypt_self("os0:kd/pamgr.skprx", "ux0:dump/out/os0-/kd/pamgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/pcbc.skprx", "ux0:dump/out/os0-/kd/pcbc.skprx", 0, 1, 0);
	decrypt_self("os0:kd/processmgr.skprx", "ux0:dump/out/os0-/kd/processmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/rtc.skprx", "ux0:dump/out/os0-/kd/rtc.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sdbgsdio.skprx", "ux0:dump/out/os0-/kd/sdbgsdio.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sdif.skprx", "ux0:dump/out/os0-/kd/sdif.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sdstor.skprx", "ux0:dump/out/os0-/kd/sdstor.skprx", 0, 1, 0);
	decrypt_self("os0:kd/smsc_proxy.skprx", "ux0:dump/out/os0-/kd/smsc_proxy.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sm_comm.skprx", "ux0:dump/out/os0-/kd/sm_comm.skprx", 0, 1, 0);
	decrypt_self("os0:kd/ss_mgr.skprx", "ux0:dump/out/os0-/kd/ss_mgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/syscon.skprx", "ux0:dump/out/os0-/kd/syscon.skprx", 0, 1, 0);
	decrypt_self("os0:kd/syslibtrace.skprx", "ux0:dump/out/os0-/kd/syslibtrace.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sysmem.skprx", "ux0:dump/out/os0-/kd/sysmem.skprx", 0, 1, 0);
	decrypt_self("os0:kd/sysstatemgr.skprx", "ux0:dump/out/os0-/kd/sysstatemgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/systimer.skprx", "ux0:dump/out/os0-/kd/systimer.skprx", 0, 1, 0);
	decrypt_self("os0:kd/threadmgr.skprx", "ux0:dump/out/os0-/kd/threadmgr.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usbdev_serial.skprx", "ux0:dump/out/os0-/kd/usbdev_serial.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usbpspcm.skprx", "ux0:dump/out/os0-/kd/usbpspcm.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usbstor.skprx", "ux0:dump/out/os0-/kd/usbstor.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usbstormg.skprx", "ux0:dump/out/os0-/kd/usbstormg.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usbstorvstor.skprx", "ux0:dump/out/os0-/kd/usbstorvstor.skprx", 0, 1, 0);
	decrypt_self("os0:kd/usb_ether_smsc.skprx", "ux0:dump/out/os0-/kd/usb_ether_smsc.skprx", 0, 1, 0);
	decrypt_self("os0:kd/vipimg.skprx", "ux0:dump/out/os0-/kd/vipimg.skprx", 0, 1, 0);
	decrypt_self("os0:kd/vnzimg.skprx", "ux0:dump/out/os0-/kd/vnzimg.skprx", 0, 1, 0);
	decrypt_self("os0:kd/wlanbt_robin_img_ax.skprx", "ux0:dump/out/os0-/kd/wlanbt_robin_img_ax.skprx", 0, 1, 0);
	decrypt_self("os0:psp2bootconfig.skprx", "ux0:dump/out/os0-/psp2bootconfig.skprx", 0, 1, 0);
	decrypt_self("os0:psp2config_dolce.skprx", "ux0:dump/out/os0-/psp2config_dolce.skprx", 0, 1, 0);
	decrypt_self("os0:psp2config_vita.skprx", "ux0:dump/out/os0-/psp2config_vita.skprx", 0, 1, 0);
	decrypt_self("os0:ue/cui_setupper.self", "ux0:dump/out/os0-/ue/cui_setupper.self", 0, 1, 1);
	decrypt_self("os0:ue/safemode.self", "ux0:dump/out/os0-/ue/safemode.self", 0, 1, 1);
	decrypt_self("os0:us/avcodec_us.suprx", "ux0:dump/out/os0-/us/avcodec_us.suprx", 0, 1, 1);
	decrypt_self("os0:us/driver_us.suprx", "ux0:dump/out/os0-/us/driver_us.suprx", 0, 1, 1);
	decrypt_self("os0:us/libgpu_es4.suprx", "ux0:dump/out/os0-/us/libgpu_es4.suprx", 0, 1, 1);
	decrypt_self("os0:us/libgxm_es4.suprx", "ux0:dump/out/os0-/us/libgxm_es4.suprx", 0, 1, 1);
	decrypt_self("os0:us/libkernel.suprx", "ux0:dump/out/os0-/us/libkernel.suprx", 0, 1, 1);
	
	//System apps and pspemu flash0
	
	decrypt_self("vs0:app/NPXS10000/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10000_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10001/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10001_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10001/np_party_app.suprx", "ux0:dump/out/vs0-/app/NPXS10001_np_party_app.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10002/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10002_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10003/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10003_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10004/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10004_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10006/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10006_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10008/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10008_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10009/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10009_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10010/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10010_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10012/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10012_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10013/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10013_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10013/gaikai-player.suprx", "ux0:dump/out/vs0-/app/NPXS10013_gaikai-player.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10013/libSceSecondScreen.suprx", "ux0:dump/out/vs0-/app/NPXS10013_libSceSecondScreen.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10014/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10014_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10015/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10015_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10015/system_settings_core.suprx", "ux0:dump/out/vs0-/app/NPXS10015_system_settings_core.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10018/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10018_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10021/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10021_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10021/tel_reg.suprx", "ux0:dump/out/vs0-/app/NPXS10021_tel_reg.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10023/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10023_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10024/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10024_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10025/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10025_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10026/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10026_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10027/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10027_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10028/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10028_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10028/pcff.skprx", "ux0:dump/out/vs0-/app/NPXS10028_pcff.skprx", 0, 1, 0);
	decrypt_self("vs0:app/NPXS10029/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10029_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10030/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10030_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10031/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10031_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10032/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10032_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10036/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10036_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10063/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10063_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10065/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10065_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10065/grief_report_dialog.suprx", "ux0:dump/out/vs0-/app/NPXS10065_grief_report_dialog.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10068/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10068_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10072/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10072_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10072/email_engine.suprx", "ux0:dump/out/vs0-/app/NPXS10072_email_engine.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10073/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10073_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10077/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10077_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10078/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10078_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10079/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10079_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10080/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10080_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10081/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10081_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10082/spawn.self", "ux0:dump/out/vs0-/app/NPXS10082_spawn.self", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10083/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10083_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10084/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10084_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10085/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10085_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10091/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10091_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10092/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10092_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10094/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10094_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10095/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10095_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10095/stitch_core_prx.suprx", "ux0:dump/out/vs0-/app/NPXS10095_stitch_core_prx.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10095/stitch_prx.suprx", "ux0:dump/out/vs0-/app/NPXS10095_stitch_prx.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10098/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10098_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10098/gaikai-player.suprx", "ux0:dump/out/vs0-/app/NPXS10098_gaikai-player.suprx", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10100/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10100_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10101/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10101_eboot.bin", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10103/ds4_pairing.self", "ux0:dump/out/vs0-/app/NPXS10103_ds4_pairing.self", 0, 1, 1);
	decrypt_self("vs0:app/NPXS10104/eboot.bin", "ux0:dump/out/vs0-/app/NPXS10104_eboot.bin", 0, 1, 1);
	
	//Plugins and VSH
	
	decrypt_self("vs0:data/external/webcore/jx_web_filtering.suprx", "ux0:dump/out/vs0-/data/external/webcore/jx_web_filtering.suprx", 0, 1, 1);
	decrypt_self("vs0:data/external/webcore/ScePsp2Compat.suprx", "ux0:dump/out/vs0-/data/external/webcore/ScePsp2Compat.suprx", 0, 1, 1);
	decrypt_self("vs0:data/external/webcore/SceWebKitModule.suprx", "ux0:dump/out/vs0-/data/external/webcore/SceWebKitModule.suprx", 0, 1, 1);
	decrypt_self("vs0:data/external/webcore/vita_jsextobj.suprx", "ux0:dump/out/vs0-/data/external/webcore/vita_jsextobj.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/activity_db.suprx", "ux0:dump/out/vs0-/sys/external/activity_db.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/adhoc_matching.suprx", "ux0:dump/out/vs0-/sys/external/adhoc_matching.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/apputil.suprx", "ux0:dump/out/vs0-/sys/external/apputil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/apputil_ext.suprx", "ux0:dump/out/vs0-/sys/external/apputil_ext.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/audiocodec.suprx", "ux0:dump/out/vs0-/sys/external/audiocodec.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/avcdec_for_player.suprx", "ux0:dump/out/vs0-/sys/external/avcdec_for_player.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/bgapputil.suprx", "ux0:dump/out/vs0-/sys/external/bgapputil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/bXCe.suprx", "ux0:dump/out/vs0-/sys/external/bXCe.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/common_gui_dialog.suprx", "ux0:dump/out/vs0-/sys/external/common_gui_dialog.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/dbrecovery_utility.suprx", "ux0:dump/out/vs0-/sys/external/dbrecovery_utility.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/dbutil.suprx", "ux0:dump/out/vs0-/sys/external/dbutil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/friend_select.suprx", "ux0:dump/out/vs0-/sys/external/friend_select.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/incoming_dialog.suprx", "ux0:dump/out/vs0-/sys/external/incoming_dialog.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/ini_file_processor.suprx", "ux0:dump/out/vs0-/sys/external/ini_file_processor.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libatrac.suprx", "ux0:dump/out/vs0-/sys/external/libatrac.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libc.suprx", "ux0:dump/out/vs0-/sys/external/libc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_calendar_review.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_calendar_review.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_cameraimport.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_cameraimport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_checkout.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_checkout.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_companion.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_companion.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_compat.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_compat.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_cross_controller.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_cross_controller.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_friendlist.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_friendlist.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_friendlist2.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_friendlist2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_game_custom_data.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_game_custom_data.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_game_custom_data_impl.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_game_custom_data_impl.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_ime.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_ime.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_invitation.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_invitation.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_invitation_impl.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_invitation_impl.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_main.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_main.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_msg.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_msg.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_near.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_near.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_netcheck.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_netcheck.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_npeula.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_npeula.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_npprofile2.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_npprofile2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_np_message.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_np_message.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_np_sns_fb.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_np_sns_fb.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_np_trophy_setup.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_np_trophy_setup.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_photoimport.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_photoimport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_photoreview.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_photoreview.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_remote_osk.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_remote_osk.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_savedata.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_savedata.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_twitter.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_twitter.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_tw_login.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_tw_login.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcdlg_videoimport.suprx", "ux0:dump/out/vs0-/sys/external/libcdlg_videoimport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libclipboard.suprx", "ux0:dump/out/vs0-/sys/external/libclipboard.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libcodecengine_perf.suprx", "ux0:dump/out/vs0-/sys/external/libcodecengine_perf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libdbg.suprx", "ux0:dump/out/vs0-/sys/external/libdbg.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libfiber.suprx", "ux0:dump/out/vs0-/sys/external/libfiber.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libfios2.suprx", "ux0:dump/out/vs0-/sys/external/libfios2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libg729.suprx", "ux0:dump/out/vs0-/sys/external/libg729.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libgameupdate.suprx", "ux0:dump/out/vs0-/sys/external/libgameupdate.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libgxm_dbg_es4.suprx", "ux0:dump/out/vs0-/sys/external/libgxm_dbg_es4.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libhandwriting.suprx", "ux0:dump/out/vs0-/sys/external/libhandwriting.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libhttp.suprx", "ux0:dump/out/vs0-/sys/external/libhttp.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libime.suprx", "ux0:dump/out/vs0-/sys/external/libime.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libipmi_nongame.suprx", "ux0:dump/out/vs0-/sys/external/libipmi_nongame.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/liblocation.suprx", "ux0:dump/out/vs0-/sys/external/liblocation.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/liblocation_extension.suprx", "ux0:dump/out/vs0-/sys/external/liblocation_extension.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/liblocation_factory.suprx", "ux0:dump/out/vs0-/sys/external/liblocation_factory.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/liblocation_internal.suprx", "ux0:dump/out/vs0-/sys/external/liblocation_internal.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libmln.suprx", "ux0:dump/out/vs0-/sys/external/libmln.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libmlnapplib.suprx", "ux0:dump/out/vs0-/sys/external/libmlnapplib.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libmlndownloader.suprx", "ux0:dump/out/vs0-/sys/external/libmlndownloader.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libnaac.suprx", "ux0:dump/out/vs0-/sys/external/libnaac.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libnet.suprx", "ux0:dump/out/vs0-/sys/external/libnet.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libnetctl.suprx", "ux0:dump/out/vs0-/sys/external/libnetctl.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libngs.suprx", "ux0:dump/out/vs0-/sys/external/libngs.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libpaf.suprx", "ux0:dump/out/vs0-/sys/external/libpaf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libpaf_web_map_view.suprx", "ux0:dump/out/vs0-/sys/external/libpaf_web_map_view.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libperf.suprx", "ux0:dump/out/vs0-/sys/external/libperf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libpgf.suprx", "ux0:dump/out/vs0-/sys/external/libpgf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libpvf.suprx", "ux0:dump/out/vs0-/sys/external/libpvf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/librazorcapture_es4.suprx", "ux0:dump/out/vs0-/sys/external/librazorcapture_es4.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/librazorhud_es4.suprx", "ux0:dump/out/vs0-/sys/external/librazorhud_es4.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/librudp.suprx", "ux0:dump/out/vs0-/sys/external/librudp.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libsas.suprx", "ux0:dump/out/vs0-/sys/external/libsas.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libsceavplayer.suprx", "ux0:dump/out/vs0-/sys/external/libsceavplayer.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceBeisobmf.suprx", "ux0:dump/out/vs0-/sys/external/libSceBeisobmf.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceBemp2sys.suprx", "ux0:dump/out/vs0-/sys/external/libSceBemp2sys.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceCompanionUtil.suprx", "ux0:dump/out/vs0-/sys/external/libSceCompanionUtil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceDtcpIp.suprx", "ux0:dump/out/vs0-/sys/external/libSceDtcpIp.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceFt2.suprx", "ux0:dump/out/vs0-/sys/external/libSceFt2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libscejpegarm.suprx", "ux0:dump/out/vs0-/sys/external/libscejpegarm.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libscejpegencarm.suprx", "ux0:dump/out/vs0-/sys/external/libscejpegencarm.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceJson.suprx", "ux0:dump/out/vs0-/sys/external/libSceJson.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libscemp4.suprx", "ux0:dump/out/vs0-/sys/external/libscemp4.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceMp4Rec.suprx", "ux0:dump/out/vs0-/sys/external/libSceMp4Rec.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceMusicExport.suprx", "ux0:dump/out/vs0-/sys/external/libSceMusicExport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceNearDialogUtil.suprx", "ux0:dump/out/vs0-/sys/external/libSceNearDialogUtil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceNearUtil.suprx", "ux0:dump/out/vs0-/sys/external/libSceNearUtil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libScePhotoExport.suprx", "ux0:dump/out/vs0-/sys/external/libScePhotoExport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libScePromoterUtil.suprx", "ux0:dump/out/vs0-/sys/external/libScePromoterUtil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceScreenShot.suprx", "ux0:dump/out/vs0-/sys/external/libSceScreenShot.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceShutterSound.suprx", "ux0:dump/out/vs0-/sys/external/libSceShutterSound.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceSqlite.suprx", "ux0:dump/out/vs0-/sys/external/libSceSqlite.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceTelephonyUtil.suprx", "ux0:dump/out/vs0-/sys/external/libSceTelephonyUtil.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceTeleportClient.suprx", "ux0:dump/out/vs0-/sys/external/libSceTeleportClient.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceTeleportServer.suprx", "ux0:dump/out/vs0-/sys/external/libSceTeleportServer.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceVideoExport.suprx", "ux0:dump/out/vs0-/sys/external/libSceVideoExport.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceVideoSearchEmpr.suprx", "ux0:dump/out/vs0-/sys/external/libSceVideoSearchEmpr.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libSceXml.suprx", "ux0:dump/out/vs0-/sys/external/libSceXml.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libshellsvc.suprx", "ux0:dump/out/vs0-/sys/external/libshellsvc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libssl.suprx", "ux0:dump/out/vs0-/sys/external/libssl.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libsulpha.suprx", "ux0:dump/out/vs0-/sys/external/libsulpha.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libsystemgesture.suprx", "ux0:dump/out/vs0-/sys/external/libsystemgesture.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libult.suprx", "ux0:dump/out/vs0-/sys/external/libult.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libvoice.suprx", "ux0:dump/out/vs0-/sys/external/libvoice.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/libvoiceqos.suprx", "ux0:dump/out/vs0-/sys/external/libvoiceqos.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/livearea_util.suprx", "ux0:dump/out/vs0-/sys/external/livearea_util.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/mail_api_for_local_libc.suprx", "ux0:dump/out/vs0-/sys/external/mail_api_for_local_libc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/near_profile.suprx", "ux0:dump/out/vs0-/sys/external/near_profile.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/notification_util.suprx", "ux0:dump/out/vs0-/sys/external/notification_util.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_activity.suprx", "ux0:dump/out/vs0-/sys/external/np_activity.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_activity_sdk.suprx", "ux0:dump/out/vs0-/sys/external/np_activity_sdk.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_basic.suprx", "ux0:dump/out/vs0-/sys/external/np_basic.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_commerce2.suprx", "ux0:dump/out/vs0-/sys/external/np_commerce2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_common.suprx", "ux0:dump/out/vs0-/sys/external/np_common.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_common_ps4.suprx", "ux0:dump/out/vs0-/sys/external/np_common_ps4.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_friend_privacylevel.suprx", "ux0:dump/out/vs0-/sys/external/np_friend_privacylevel.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_kdc.suprx", "ux0:dump/out/vs0-/sys/external/np_kdc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_manager.suprx", "ux0:dump/out/vs0-/sys/external/np_manager.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_matching2.suprx", "ux0:dump/out/vs0-/sys/external/np_matching2.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_message.suprx", "ux0:dump/out/vs0-/sys/external/np_message.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_message_contacts.suprx", "ux0:dump/out/vs0-/sys/external/np_message_contacts.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_message_dialog_impl.suprx", "ux0:dump/out/vs0-/sys/external/np_message_dialog_impl.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_message_padding.suprx", "ux0:dump/out/vs0-/sys/external/np_message_padding.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_party.suprx", "ux0:dump/out/vs0-/sys/external/np_party.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_ranking.suprx", "ux0:dump/out/vs0-/sys/external/np_ranking.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_signaling.suprx", "ux0:dump/out/vs0-/sys/external/np_signaling.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_sns_facebook.suprx", "ux0:dump/out/vs0-/sys/external/np_sns_facebook.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_trophy.suprx", "ux0:dump/out/vs0-/sys/external/np_trophy.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_tus.suprx", "ux0:dump/out/vs0-/sys/external/np_tus.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_utility.suprx", "ux0:dump/out/vs0-/sys/external/np_utility.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/np_webapi.suprx", "ux0:dump/out/vs0-/sys/external/np_webapi.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/party_member_list.suprx", "ux0:dump/out/vs0-/sys/external/party_member_list.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/psmkdc.suprx", "ux0:dump/out/vs0-/sys/external/psmkdc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/pspnet_adhoc.suprx", "ux0:dump/out/vs0-/sys/external/pspnet_adhoc.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/signin_ext.suprx", "ux0:dump/out/vs0-/sys/external/signin_ext.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/sqlite.suprx", "ux0:dump/out/vs0-/sys/external/sqlite.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/store_checkout_plugin.suprx", "ux0:dump/out/vs0-/sys/external/store_checkout_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/trigger_util.suprx", "ux0:dump/out/vs0-/sys/external/trigger_util.suprx", 0, 1, 1);
	decrypt_self("vs0:sys/external/web_ui_plugin.suprx", "ux0:dump/out/vs0-/sys/external/web_ui_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/app_settings.suprx", "ux0:dump/out/vs0-/vsh/common/app_settings.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/auth_plugin.suprx", "ux0:dump/out/vs0-/vsh/common/auth_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/av_content_handler.suprx", "ux0:dump/out/vs0-/vsh/common/av_content_handler.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/backup_restore.suprx", "ux0:dump/out/vs0-/vsh/common/backup_restore.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/content_operation.suprx", "ux0:dump/out/vs0-/vsh/common/content_operation.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/dbrecovery_plugin.suprx", "ux0:dump/out/vs0-/vsh/common/dbrecovery_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/dbsetup.suprx", "ux0:dump/out/vs0-/vsh/common/dbsetup.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libBEAVCorePlayer.suprx", "ux0:dump/out/vs0-/vsh/common/libBEAVCorePlayer.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libFflMp4.suprx", "ux0:dump/out/vs0-/vsh/common/libFflMp4.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libical.suprx", "ux0:dump/out/vs0-/vsh/common/libical.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libicalss.suprx", "ux0:dump/out/vs0-/vsh/common/libicalss.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmarlin.suprx", "ux0:dump/out/vs0-/vsh/common/libmarlin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmarlindownloader.suprx", "ux0:dump/out/vs0-/vsh/common/libmarlindownloader.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmarlin_pb.suprx", "ux0:dump/out/vs0-/vsh/common/libmarlin_pb.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmtp.suprx", "ux0:dump/out/vs0-/vsh/common/libmtp.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmtphttp.suprx", "ux0:dump/out/vs0-/vsh/common/libmtphttp.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libmtphttp_wrapper.suprx", "ux0:dump/out/vs0-/vsh/common/libmtphttp_wrapper.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libSenvuabsFFsdk.suprx", "ux0:dump/out/vs0-/vsh/common/libSenvuabsFFsdk.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/libvideoprofiler.suprx", "ux0:dump/out/vs0-/vsh/common/libvideoprofiler.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mail_api_for_local.suprx", "ux0:dump/out/vs0-/vsh/common/mail_api_for_local.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/AACPromoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/AACPromoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/bmp_promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/bmp_promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/gif_promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/gif_promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/jpeg_promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/jpeg_promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/meta_gen.suprx", "ux0:dump/out/vs0-/vsh/common/mms/meta_gen.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/Mp3Promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/Mp3Promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/MsvPromoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/MsvPromoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/png_promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/png_promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/RiffPromoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/RiffPromoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/SensMe.suprx", "ux0:dump/out/vs0-/vsh/common/mms/SensMe.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mms/tiff_promoter.suprx", "ux0:dump/out/vs0-/vsh/common/mms/tiff_promoter.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mtpr3.suprx", "ux0:dump/out/vs0-/vsh/common/mtpr3.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/mtp_client.suprx", "ux0:dump/out/vs0-/vsh/common/mtp_client.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/common/np_grief_report.suprx", "ux0:dump/out/vs0-/vsh/common/np_grief_report.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/game/gamecard_installer_plugin.suprx", "ux0:dump/out/vs0-/vsh/game/gamecard_installer_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/game/gamedata_plugin.suprx", "ux0:dump/out/vs0-/vsh/game/gamedata_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/initialsetup/initialsetup.self", "ux0:dump/out/vs0-/vsh/initialsetup/initialsetup.self", 0, 1, 1);
	decrypt_self("vs0:vsh/online_storage/online_storage_plugin.suprx", "ux0:dump/out/vs0-/vsh/online_storage/online_storage_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/auth_reset_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/auth_reset_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/idu_update_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/idu_update_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/ime_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/ime_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/impose_net_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/impose_net_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/liblocation_permission.suprx", "ux0:dump/out/vs0-/vsh/shell/liblocation_permission.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/liblocation_provider.suprx", "ux0:dump/out/vs0-/vsh/shell/liblocation_provider.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/livespace_db.suprx", "ux0:dump/out/vs0-/vsh/shell/livespace_db.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/location_dialog_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/location_dialog_plugin.suprx", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/shell.self", "ux0:dump/out/vs0-/vsh/shell/shell.self", 0, 1, 1);
	decrypt_self("vs0:vsh/shell/telephony/initial_check/tel_initial_check_plugin.suprx", "ux0:dump/out/vs0-/vsh/shell/telephony/initial_check/tel_initial_check_plugin.suprx", 0, 1, 1);

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
