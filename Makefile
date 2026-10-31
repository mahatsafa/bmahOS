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
S_SRCS := $(KERNEL_DIR)/gdt.S $(KERNEL_DIR)/interrupt.S $(KERNEL_DIR)/task.S $(KERNEL_DIR)/userbin.S

C_OBJS := $(patsubst $(KERNEL_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SRCS))
S_OBJS := $(patsubst $(KERNEL_DIR)/%.S,$(BUILD_DIR)/%.o,$(S_SRCS))
OBJS   := $(C_OBJS) $(S_OBJS)

KERNEL_ELF := $(BUILD_DIR)/kernel.elf
ISO_OUT    := $(BUILD_DIR)/bmahOS.iso

QEMU := $(shell command -v qemu-system-x86_64 2>/dev/null || echo /usr/libexec/qemu-kvm)
OVMF := /usr/share/edk2/ovmf/OVMF_CODE.fd

.PHONY: all clean run iso test host-test fuzz fuzz-regress

all: iso

$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.c $(HDRS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

$(BUILD_DIR)/%.o: $(KERNEL_DIR)/%.S
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

# P5-1: program user (userspace/*.c) -> biner datar di 0x400000, ditanam lewat
# kernel/userbin.S. -O2 boleh (bukan kode kernel); tanpa SSE, tanpa panggilan mem*.
USER_CFLAGS := -std=gnu11 -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie -m64 \
               -march=x86-64 -mno-mmx -mno-sse -mno-sse2 -O2 -fno-tree-loop-distribute-patterns \
               -fno-asynchronous-unwind-tables -Wall -Wextra -Werror
USER_PROGS  := udpgema

$(BUILD_DIR)/user/%.elf: userspace/%.c userspace/bm.h userspace/user.ld
	@mkdir -p $(BUILD_DIR)/user
	$(CC) $(USER_CFLAGS) -c $< -o $(BUILD_DIR)/user/$*.o
	$(LD) -nostdlib -static -m elf_x86_64 -T userspace/user.ld $(BUILD_DIR)/user/$*.o -o $@

$(BUILD_DIR)/user/%.bin: $(BUILD_DIR)/user/%.elf
	objcopy -O binary -j .text $< $@

$(BUILD_DIR)/userbin.o: $(addprefix $(BUILD_DIR)/user/,$(addsuffix .bin,$(USER_PROGS)))

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
HOST_TESTS  := crypto kprintf net auth entropy ktimer audit fat32 config panic metrics logdisk \
               watchdog pmm fbcon pci acpi rtc filter sntp dns monitor dhcp sock
host_srcs_crypto  := $(KERNEL_DIR)/crypto.c
host_srcs_kprintf := $(KERNEL_DIR)/kprintf.c
host_srcs_net     := $(KERNEL_DIR)/ktimer.c $(KERNEL_DIR)/kprintf.c \
                     $(KERNEL_DIR)/tls.c   # C3c: timer retransmisi, D9b: TLS 7780
host_libs_net      = $(HOST_BEARSSL_LIB)   # '=': didefinisikan di bawah
host_deps_net     := $(KERNEL_DIR)/net.c $(KERNEL_DIR)/netcon.c   # di-#include oleh test_net.c (akses static)
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
host_srcs_metrics := $(KERNEL_DIR)/kprintf.c
host_deps_metrics := $(KERNEL_DIR)/metrics.c   # R3: di-#include oleh test_metrics.c
host_srcs_logdisk := $(KERNEL_DIR)/crypto.c $(KERNEL_DIR)/kprintf.c
host_deps_logdisk := $(KERNEL_DIR)/logdisk.c   # R4: di-#include oleh test_logdisk.c
host_srcs_watchdog := $(KERNEL_DIR)/kprintf.c
host_deps_watchdog := $(KERNEL_DIR)/watchdog.c # R5: di-#include oleh test_watchdog.c
host_srcs_pmm     := $(KERNEL_DIR)/kprintf.c
host_deps_pmm     := $(KERNEL_DIR)/pmm.c tests/host/limine.h   # R6-3: limine.h pengganti
host_deps_fbcon   := $(KERNEL_DIR)/fbcon.c $(KERNEL_DIR)/fbfont.h   # P1: di-#include oleh test_fbcon.c
host_srcs_pci     := $(KERNEL_DIR)/kprintf.c
host_deps_pci     := $(KERNEL_DIR)/pci.c       # P2: di-#include oleh test_pci.c
host_srcs_acpi    := $(KERNEL_DIR)/kprintf.c
host_deps_acpi    := $(KERNEL_DIR)/acpi.c      # P2: di-#include oleh test_acpi.c
host_srcs_rtc     := $(KERNEL_DIR)/kprintf.c
host_deps_rtc     := $(KERNEL_DIR)/rtc.c       # P3-1: di-#include oleh test_rtc.c
host_srcs_filter  := $(KERNEL_DIR)/kprintf.c
host_deps_filter  := $(KERNEL_DIR)/filter.c    # P4: di-#include oleh test_filter.c
host_srcs_sntp    := $(KERNEL_DIR)/kprintf.c $(KERNEL_DIR)/rtc.c
host_deps_sntp    := $(KERNEL_DIR)/sntp.c      # P3-2: di-#include oleh test_sntp.c
host_srcs_dns     := $(KERNEL_DIR)/kprintf.c
host_deps_dns     := $(KERNEL_DIR)/dns.c       # P3-3: di-#include oleh test_dns.c
host_srcs_monitor := $(KERNEL_DIR)/kprintf.c $(KERNEL_DIR)/rtc.c
host_deps_monitor := $(KERNEL_DIR)/monitor.c   # P6-1: di-#include oleh test_monitor.c
host_srcs_dhcp    := $(KERNEL_DIR)/kprintf.c
host_deps_dhcp    := $(KERNEL_DIR)/dhcp.c      # P3-4: di-#include oleh test_dhcp.c
host_srcs_sock    := $(KERNEL_DIR)/kprintf.c
host_deps_sock    := $(KERNEL_DIR)/sock.c      # P5-1: di-#include oleh test_sock.c

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
	$(MAKE) --no-print-directory fuzz-regress || fail=1; \
	if [ $$fail -eq 0 ]; then echo ">> host-test: semua lulus"; \
	else echo ">> host-test: ADA YANG GAGAL"; exit 1; fi

# R7: fuzzing libFuzzer di host. tests/fuzz/fuzz_X.c meng-#include tests/host/test_X.c
# (main dilewati BMAHOS_FUZZ). fuzz_X = -fsanitize=fuzzer; regr_X = tests/fuzz/driver.c
# (sekali jalan per file, juga "-s DIR" = tulis korpus awal).
#   make fuzz [FUZZ_TARGETS="net auth"] [FUZZ_TIME=600]: tiap target FUZZ_TIME detik,
#     korpus kerja build/fuzz/corpus/X, temuan build/fuzz/crash-X-*, log build/fuzz/X.log
#   make fuzz-regress: korpus awal + tests/fuzz/regress/X (temuan yang sudah diperbaiki)
FUZZ_TARGETS ?= net auth config fat32 logdisk dhcp dns sntp filter   # + parser Fase 5
FUZZ_TIME    ?= 600
FUZZ_BUILD   := $(BUILD_DIR)/fuzz
FUZZ_CFLAGS   = $(HOST_CFLAGS) -DBMAHOS_FUZZ -Wno-unused-function -Itests/fuzz
FUZZ_DEPS    := tests/fuzz/fuzz.h tests/host/stubs.c tests/host/test.h tests/host/drbg_vectors.h \
                tests/host/tls_test_keys.h $(HDRS)
fuzz_maxlen_net := 8192

$(FUZZ_BUILD)/fuzz_%: tests/fuzz/fuzz_%.c tests/host/test_%.c $(FUZZ_DEPS) $$(host_srcs_$$*) $$(host_deps_$$*) $$(host_libs_$$*)
	@mkdir -p $(FUZZ_BUILD)
	$(HOST_CC) $(FUZZ_CFLAGS) -fsanitize=fuzzer $< tests/host/stubs.c $(host_srcs_$*) $(host_libs_$*) -o $@

$(FUZZ_BUILD)/regr_%: tests/fuzz/fuzz_%.c tests/fuzz/driver.c tests/host/test_%.c $(FUZZ_DEPS) $$(host_srcs_$$*) $$(host_deps_$$*) $$(host_libs_$$*)
	@mkdir -p $(FUZZ_BUILD)
	$(HOST_CC) $(FUZZ_CFLAGS) $< tests/fuzz/driver.c tests/host/stubs.c $(host_srcs_$*) $(host_libs_$*) -o $@

fuzz-regress: $(addprefix $(FUZZ_BUILD)/regr_,$(FUZZ_TARGETS))
	@for t in $(FUZZ_TARGETS); do s=$(FUZZ_BUILD)/seeds/$$t; rm -rf $$s; mkdir -p $$s; \
	    $(FUZZ_BUILD)/regr_$$t -s $$s && $(FUZZ_BUILD)/regr_$$t $$s tests/fuzz/regress/$$t \
	    || { echo "fuzz-regress $$t GAGAL"; exit 1; }; done

fuzz: $(addprefix $(FUZZ_BUILD)/fuzz_,$(FUZZ_TARGETS)) $(addprefix $(FUZZ_BUILD)/regr_,$(FUZZ_TARGETS))
	@fail=0; for t in $(FUZZ_TARGETS); do s=$(FUZZ_BUILD)/seeds/$$t; c=$(FUZZ_BUILD)/corpus/$$t; \
	    rm -rf $$s; mkdir -p $$s $$c; $(FUZZ_BUILD)/regr_$$t -s $$s || exit 1; \
	    case $$t in net) ml="-max_len=$(fuzz_maxlen_net)";; *) ml="";; esac; \
	    dict=""; [ -f tests/fuzz/$$t.dict ] && dict="-dict=tests/fuzz/$$t.dict"; \
	    echo ">> fuzz $$t $(FUZZ_TIME) s (log $(FUZZ_BUILD)/$$t.log)"; \
	    if $(FUZZ_BUILD)/fuzz_$$t -max_total_time=$(FUZZ_TIME) -print_final_stats=1 $$ml $$dict \
	        -artifact_prefix=$(FUZZ_BUILD)/crash-$$t- $$c $$s > $(FUZZ_BUILD)/$$t.log 2>&1; then \
	        grep -aE '^(#[0-9]+[[:space:]]+DONE|stat::number_of_executed_units)' \
	            $(FUZZ_BUILD)/$$t.log | tr '\n' ' '; echo; \
	    else echo "fuzz $$t: TEMUAN"; grep -m3 -E 'ERROR|FUZZ:|SUMMARY' $(FUZZ_BUILD)/$$t.log; \
	        ls $(FUZZ_BUILD)/crash-$$t-* 2>/dev/null; fail=1; fi; done; \
	if [ $$fail -eq 0 ]; then echo ">> fuzz: tanpa temuan"; else echo ">> fuzz: ADA TEMUAN"; exit 1; fi

clean:
	rm -rf $(BUILD_DIR)
