TITLE_ID = NIDUMP001
TARGET = mDump
PSVITAIP = 192.168.137.84

PLUGIN_OBJS = kernel.o
HEADERS = $(wildcard *.h)

PLUGIN_LIBS = -Llibtaihen_stub.a -lSceSysclibForDriver_stub -lSceModulemgrForKernel_stub -lSceIofilemgrForDriver_stub -lSceLibc_stub -lSceSysmemForDriver_stub -lSceSblAuthMgrForKernel_stub -lSceSysmemForKernel_stub

PREFIX  = arm-vita-eabi
CC      = $(PREFIX)-gcc
CFLAGS  = -Wl,-q -Wall -O3
ASFLAGS = $(CFLAGS)

all: kDump.skprx

kDump.skprx: kDump.velf
	vita-make-fself $< $@

kDump.velf: kDump.elf
	vita-elf-create -e exports.yml $< $@

kDump.elf: $(PLUGIN_OBJS)
	$(CC) $(CFLAGS) $^ $(PLUGIN_LIBS) -o $@ -nostdlib

clean:
	@rm -rf *.velf *.elf *.vpk *.skprx $(MAIN_OBJS) $(PLUGIN_OBJS) param.sfo eboot.bin

send: eboot.bin
	curl -T kDump.skprx ftp://$(PSVITAIP):1337/ux0:/tai/
	@echo "Sent."
