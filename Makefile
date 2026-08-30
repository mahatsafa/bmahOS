KERNEL_DIR   := kernel
BUILD_DIR    := build
ISO_ROOT     := $(BUILD_DIR)/iso_root
LIMINE_BIN   := tools/limine/bin
LIMINE_INC   := tools/limine/limine-protocol/include

CC := gcc
LD := ld

CFLAGS := -std=gnu11 -ffreestanding -fno-stack-protector -fno-stack-check -fno-pic -fno-pie -m64 -march=x86-64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=kernel -Wall -Wextra -I$(KERNEL_DIR) -I$(LIMINE_INC) -c

LDFLAGS := -nostdlib -static -m elf_x86_64 -z max-page-size=0x1000 -T linker.ld

C_SRCS := $(KERNEL_DIR)/kernel.c
S_SRCS := $(KERNEL_DIR)/gdt.S $(KERNEL_DIR)/interrupt.S

C_OBJS := $(patsubst $(KERNEL_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
S_OBJS := $(patsubst $(KERNEL_DIR)/%.S,$(BUILD_DIR)/%.o,$(S_SRCS))
OBJS   := $(C_OBJS) $(S_OBJS)

KERNEL_ELF := $(BUILD_DIR)/kernel.elf
ISO_OUT    := $(BUILD_DIR)/bmahOS.iso

QEMU := $(shell command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)
OVMF := /usr/share/edk2/ovmf/OVMF_CODE.fd

.PHONY: all clean run iso

all: iso

$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.c
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

clean:
	rm -rf $(BUILD_DIR)
