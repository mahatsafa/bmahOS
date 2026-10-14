KERNEL_DIR   := kernel
BUILD_DIR    := build
ISO_ROOT     := $(BUILD_DIR)/iso_root
LIMINE_BIN   := tools/limine/bin
LIMINE_INC   := tools/limine/limine-protocol/include

CC := gcc
LD := ld

# D9a: ARCH_CFLAGS dipakai juga untuk BearSSL (harus sama: tanpa SSE, mcmodel=kernel).
ARCH_CFLAGS := -std=gnu11 -ffreestanding -fno-stack-protector -fno-stack-check -fno-pic -fno-pie -m64 -march=x86-64 -mno-red-zone -mno-mmx -mno-sse -mno-sse2 -mcmodel=kernel
# D9b: kernel/tls.c memakai header BearSSL; string.h dari kernel/compat.
# R1: frame pointer eksplisit untuk stack trace panic (tanpa -O gcc sudah
# memakainya; BearSSL -O2 butuh flag ini supaya rantai rbp tidak putus).
CFLAGS := $(ARCH_CFLAGS) -fno-omit-frame-pointer -Wall -Wextra -I$(KERNEL_DIR) -I$(LIMINE_INC) \
          -I$(KERNEL_DIR)/compat -Ithird_party/bearssl/inc -c

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

# D9a: BearSSL (third_party/bearssl, commit tercatat di 3RDPARTY.md, tidak diubah).
# Semua src/*.c -> build/libbearssl.a dengan -O2 (kode kernel sendiri tetap tanpa -O).
# Konfigurasi: tanpa SSE2/AES-NI/POWER8/RDRAND, tanpa RNG/waktu OS; BR_INT128 nyala.
# string.h dari kernel/compat (deklarasi mem* dan strlen; implementasi di kernel).
BEARSSL_DIR  := third_party/bearssl
BEARSSL_DEFS := -DBR_RDRAND=0 -DBR_USE_GETENTROPY=0 -DBR_USE_URANDOM=0 \
                -DBR_USE_WIN32_RAND=0 -DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0 \
                -DBR_AES_X86NI=0 -DBR_SSE2=0 -DBR_POWER8=0 -DBR_INT128=1
BEARSSL_INC  := -I$(BEARSSL_DIR)/inc -I$(BEARSSL_DIR)/src
BEARSSL_SRCS := $(sort $(shell find $(BEARSSL_DIR)/src -name '*.c'))
BEARSSL_HDRS := $(wildcard $(BEARSSL_DIR)/inc/*.h) $(BEARSSL_DIR)/src/inner.h \
                $(BEARSSL_DIR)/src/config.h $(KERNEL_DIR)/compat/string.h
BEARSSL_OBJS := $(patsubst $(BEARSSL_DIR)/src/%.c,$(BUILD_DIR)/bearssl/%.o,$(BEARSSL_SRCS))
BEARSSL_LIB  := $(BUILD_DIR)/libbearssl.a

$(BUILD_DIR)/bearssl/%.o: $(BEARSSL_DIR)/src/%.c $(BEARSSL_HDRS)
	@mkdir -p $(dir $@)
	@$(CC) $(ARCH_CFLAGS) -O2 -fno-omit-frame-pointer -I$(KERNEL_DIR)/compat $(BEARSSL_INC) $(BEARSSL_DEFS) -c $< -o $@

$(BEARSSL_LIB): $(BEARSSL_OBJS)
	@rm -f $@
	ar rcs $@ $(BEARSSL_OBJS)
	@echo ">> BearSSL: $(words $(BEARSSL_OBJS)) objek -> $@"

$(KERNEL_ELF): $(OBJS) $(BEARSSL_LIB) linker.ld
	$(LD) $(LDFLAGS) $(OBJS) $(BEARSSL_LIB) -o $(KERNEL_ELF)

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

test: iso $(BEARSSL_LIB)
	QEMU=$(QEMU) OVMF_CODE=$(OVMF) tests/qemu-smoke.sh

# F1.7: uji unit fungsi murni di host (Linux), dengan ASan + UBSan.
# Tiap tests/host/test_X.c dikompilasi bersama modul kernel yang diujinya
# dan tests/host/stubs.c. HOST_CC=gcc juga bisa bila libasan/libubsan ada.
HOST_CC     ?= clang
HOST_BUILD  := $(BUILD_DIR)/host
HOST_CFLAGS := -std=gnu11 -g -O1 -Wall -Wextra -Werror -fno-omit-frame-pointer \
               -fsanitize=address,undefined -fno-sanitize-recover=all \
               -DBMAHOS_HOST_TEST -I$(KERNEL_DIR) -Itests/host -Ithird_party/bearssl/inc
HOST_TESTS  := crypto kprintf net auth entropy ktimer audit fat32 config panic
host_srcs_crypto  := $(KERNEL_DIR)/crypto.c
host_srcs_kprintf := $(KERNEL_DIR)/kprintf.c
host_srcs_net     := $(KERNEL_DIR)/ktimer.c $(KERNEL_DIR)/kprintf.c \
                     $(KERNEL_DIR)/tls.c   # C3c: timer retransmisi, D9b: TLS 7780
host_libs_net      = $(HOST_BEARSSL_LIB)   # '=': didefinisikan di bawah
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
host_srcs_config  := $(KERNEL_DIR)/kprintf.c
host_deps_config  := $(KERNEL_DIR)/config.c    # di-#include oleh test_config.c
host_srcs_panic   := $(KERNEL_DIR)/kprintf.c
host_deps_panic   := $(KERNEL_DIR)/panic.c     # R1: di-#include oleh test_panic.c

# D9a: BearSSL versi host (clang + ASan/UBSan) dan test_crypto upstream untuk
# implementasi yang dipakai profil TLS D9. -fno-sanitize=function: vtable BearSSL
# memanggil lewat pointer bertipe kelas (disengaja); alignment: BR_LE_UNALIGNED x86.
HOST_BEARSSL_CFLAGS := -std=gnu11 -g -O1 -fsanitize=address,undefined \
               -fno-sanitize=function,alignment -fno-sanitize-recover=all \
               $(BEARSSL_DEFS) $(BEARSSL_INC)
HOST_BEARSSL_OBJS := $(patsubst $(BEARSSL_DIR)/src/%.c,$(HOST_BUILD)/bearssl/%.o,$(BEARSSL_SRCS))
HOST_BEARSSL_LIB  := $(HOST_BUILD)/libbearssl.a
BEARSSL_KAT := SHA256 HMAC HMAC_DRBG PRF AES_ct64 GHASH_ctmul64 GCM ChaCha20_ct \
               Poly1305_ctmulq EC_p256_m64 ECDSA_i31
# baris "done." yang diharapkan (EC_p256_m64 punya baris keygen sendiri)
BEARSSL_KAT_LINES := 12

$(HOST_BUILD)/bearssl/%.o: $(BEARSSL_DIR)/src/%.c $(BEARSSL_HDRS)
	@mkdir -p $(dir $@)
	@$(HOST_CC) $(HOST_BEARSSL_CFLAGS) -c $< -o $@

$(HOST_BEARSSL_LIB): $(HOST_BEARSSL_OBJS)
	@rm -f $@
	ar rcs $@ $(HOST_BEARSSL_OBJS)

$(HOST_BUILD)/bearssl_test_crypto: $(BEARSSL_DIR)/test/test_crypto.c $(HOST_BEARSSL_LIB)
	$(HOST_CC) $(HOST_BEARSSL_CFLAGS) $< $(HOST_BEARSSL_LIB) -o $@

.SECONDEXPANSION:
$(HOST_BUILD)/test_%: tests/host/test_%.c tests/host/stubs.c tests/host/test.h tests/host/drbg_vectors.h tests/host/tls_test_keys.h $(HDRS) $$(host_srcs_$$*) $$(host_deps_$$*) $$(host_libs_$$*)
	@mkdir -p $(HOST_BUILD)
	$(HOST_CC) $(HOST_CFLAGS) tests/host/test_$*.c tests/host/stubs.c $(host_srcs_$*) $(host_libs_$*) -o $@

host-test: $(addprefix $(HOST_BUILD)/test_,$(HOST_TESTS)) $(HOST_BUILD)/bearssl_test_crypto
	@fail=0; for t in $(addprefix $(HOST_BUILD)/test_,$(HOST_TESTS)); do $$t || fail=1; done; \
	log=$(HOST_BUILD)/bearssl_test_crypto.log; \
	if $(HOST_BUILD)/bearssl_test_crypto $(BEARSSL_KAT) > $$log 2>&1 && \
	   [ "$$(grep -c 'done\.$$' $$log)" -eq $(BEARSSL_KAT_LINES) ]; then \
	    echo "bearssl      $(BEARSSL_KAT_LINES) uji test_crypto upstream lulus"; \
	else echo "bearssl      GAGAL (lihat $$log)"; tail -5 $$log; fail=1; fi; \
	if [ $$fail -eq 0 ]; then echo ">> host-test: semua lulus"; \
	else echo ">> host-test: ADA YANG GAGAL"; exit 1; fi

clean:
	rm -rf $(BUILD_DIR)
