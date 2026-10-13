KERNEL_DIR   := kernel
BUILD_DIR    := build
ISO_ROOT     := $(BUILD_DIR)/iso_root
LIMINE_BIN   := tools/limine/bin
LIMINE_INC   := tools/limine/limine-protocol/include

CC := gcc
LD := ld

CFLAGS := -std=gnu11 -ffreestanding -fno-stack-protector -fno-stack-check -fno-pic -fno-pie -m64 -march=x86-64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=kernel -Wall -Wextra -I$(KERNEL_DIR) -I$(LIMINE_INC) -c

ifeq ($(PROD),1)
CFLAGS += -DBMAHOS_PROD
endif

ifeq ($(NOIRQ),1)
CFLAGS += -DBMAHOS_NOIRQ
endif

ifeq ($(NORDRAND),1)
CFLAGS += -DBMAHOS_NORDRAND
endif

ifeq ($(NOKBDRESET),1)
CFLAGS += -DBMAHOS_NOKBDRESET
endif

ifeq ($(NOACPIRESET),1)
CFLAGS += -DBMAHOS_NOACPIRESET
endif

ifeq ($(LEGACYCTR),1)
CFLAGS += -DBMAHOS_LEGACYCTR
endif

ifeq ($(NXTEST),1)
CFLAGS += -DBMAHOS_NXTEST
endif

ifeq ($(ASSERTTEST),1)
CFLAGS += -DBMAHOS_ASSERTTEST
endif

ifeq ($(NOENTROPY),1)
CFLAGS += -DBMAHOS_NOENTROPY
endif

LDFLAGS := -nostdlib -static -m elf_x86_64 -z max-page-size=0x1000 -T linker.ld

C_SRCS := $(wildcard $(KERNEL_DIR)/*.c)
HDRS   := $(wildcard $(KERNEL_DIR)/*.h)
S_SRCS := $(KERNEL_DIR)/gdt.S $(KERNEL_DIR)/interrupt.S $(KERNEL_DIR)/task.S

C_OBJS := $(patsubst $(KERNEL_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
S_OBJS := $(patsubst $(KERNEL_DIR)/%.S,$(BUILD_DIR)/%.o,$(S_SRCS))
OBJS   := $(C_OBJS) $(S_OBJS)

KERNEL_ELF := $(BUILD_DIR)/kernel.elf
ISO_OUT    := $(BUILD_DIR)/bmahOS.iso

QEMU := $(shell command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)
OVMF := /usr/share/edk2/ovmf/OVMF_CODE.fd

.PHONY: all clean run iso test host-test

all: iso

$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.c $(HDRS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.S
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(KERNEL_ELF): $(OBJS) linker.ld
	$(LD) $(LDFLAGS) $(OBJS) -o $(KERNEL_ELF)

iso: $(KERNEL_ELF)
	@mkdir -p $(ISO_ROOT)/boot
	@mkdir -p $(ISO_ROOT)/EFI/BOOT
	cp $(KERNEL_ELF) $(ISO_ROOT)/boot/kernel.elf
	cp $(KERNEL_DIR)/limine.conf $(ISO_ROOT)/boot/limine.conf
	cp $(LIMINE_BIN)/limine-uefi-cd.bin $(ISO_ROOT)/boot/limine-uefi-cd.bin
	cp $(LIMINE_BIN)/BOOTX64.EFI $(ISO_ROOT)/EFI/BOOT/BOOTX64.EFI
	xorriso -as mkisofs -R -r -J \
		--efi-boot boot/limine-uefi-cd.bin \
		-efi-boot-part --efi-boot-image --protective-msdos-label \
		$(ISO_ROOT) -o $(ISO_OUT)
	@echo ">> ISO selesai: $(ISO_OUT)"

run: iso
	@mkdir -p $(BUILD_DIR)/ovmf
	@cp -n /usr/share/edk2/ovmf/OVMF_VARS.fd $(BUILD_DIR)/ovmf/OVMF_VARS.fd
	$(QEMU) -machine q35 -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd -drive if=pflash,format=raw,file=$(BUILD_DIR)/ovmf/OVMF_VARS.fd -cdrom $(ISO_OUT) -serial stdio -m 512M

test: iso
	QEMU=$(QEMU) OVMF_CODE=$(OVMF) tests/qemu-smoke.sh

# F1.7: uji unit fungsi murni di host (Linux), dengan ASan + UBSan.
# Tiap tests/host/test_X.c dikompilasi bersama modul kernel yang diujinya
# dan tests/host/stubs.c. HOST_CC=gcc juga bisa bila libasan/libubsan ada.
HOST_CC     ?= clang
HOST_BUILD  := $(BUILD_DIR)/host
HOST_CFLAGS := -std=gnu11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
               -fsanitize=address,undefined -fno-sanitize-recover=all \
               -DBMAHOS_HOST_TEST -I$(KERNEL_DIR) -Itests/host
HOST_TESTS  := crypto kprintf net auth entropy ktimer audit fat32
host_srcs_crypto  := $(KERNEL_DIR)/crypto.c
host_srcs_kprintf := $(KERNEL_DIR)/kprintf.c
host_srcs_net     := $(KERNEL_DIR)/ktimer.c $(KERNEL_DIR)/kprintf.c   # C3c: timer retransmisi
host_deps_net     := $(KERNEL_DIR)/net.c   # di-#include oleh test_net.c (akses fungsi static)
host_srcs_auth    := $(KERNEL_DIR)/crypto.c $(KERNEL_DIR)/audit.c $(KERNEL_DIR)/kprintf.c
host_deps_auth    := $(KERNEL_DIR)/auth.c  # di-#include oleh test_auth.c
host_srcs_entropy := $(KERNEL_DIR)/crypto.c $(KERNEL_DIR)/kprintf.c
host_deps_entropy := $(KERNEL_DIR)/entropy.c   # di-#include oleh test_entropy.c
host_srcs_ktimer  := $(KERNEL_DIR)/kprintf.c
host_deps_ktimer  := $(KERNEL_DIR)/ktimer.c    # di-#include oleh test_ktimer.c
host_srcs_audit   := $(KERNEL_DIR)/kprintf.c
host_deps_audit   := $(KERNEL_DIR)/audit.c     # di-#include oleh test_audit.c
host_srcs_fat32   := $(KERNEL_DIR)/kprintf.c
host_deps_fat32   := $(KERNEL_DIR)/fat32.c $(KERNEL_DIR)/fscmd.c   # D6: butuh mkfs.vfat, mtools, fsck.fat

.SECONDEXPANSION:
$(HOST_BUILD)/test_%: tests/host/test_%.c tests/host/stubs.c tests/host/test.h tests/host/drbg_vectors.h $(HDRS) $$(host_srcs_$$*) $$(host_deps_$$*)
	@mkdir -p $(HOST_BUILD)
	$(HOST_CC) $(HOST_CFLAGS) tests/host/test_$*.c tests/host/stubs.c $(host_srcs_$*) -o $@

host-test: $(addprefix $(HOST_BUILD)/test_,$(HOST_TESTS))
	@fail=0; for t in $^; do $$t || fail=1; done; \
	if [ $$fail -eq 0 ]; then echo ">> host-test: semua lulus"; \
	else echo ">> host-test: ADA YANG GAGAL"; exit 1; fi

clean:
	rm -rf $(BUILD_DIR)
