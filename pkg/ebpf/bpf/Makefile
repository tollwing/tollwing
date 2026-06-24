CFLAGS := -Wall -Werror -O2 -g

BPF_DIR := pkg/ebpf/bpf
OUTPUT_DIR_X86 := $(BPF_DIR)/bin/x86
OUTPUT_DIR_ARM := $(BPF_DIR)/bin/arm64
INCLUDE_DIR := include

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_TARGET := bpfel

BPF_CFLAGS := $(CFLAGS) -target $(BPF_TARGET) -I$(INCLUDE_DIR) -I.

ENTRYPOINT_SRC := $(BPF_DIR)/tollwing.bpf.c
SRC_FILES := $(wildcard $(BPF_DIR)/*.c) \
             $(wildcard $(BPF_DIR)/*.h) \
             $(wildcard include/bpf/*.h) \
             $(wildcard vmlinux/*.h)

OUTPUTS_X86 := $(OUTPUT_DIR_X86)/tollwing.bpf.o
OUTPUTS_ARM := $(OUTPUT_DIR_ARM)/tollwing.bpf.o
OUTPUTS := $(OUTPUTS_X86) $(OUTPUTS_ARM)

.PHONY: bpf-all bpf-clean

bpf-all: $(OUTPUTS)

$(OUTPUT_DIR_X86)/tollwing.bpf.o: $(ENTRYPOINT_SRC) $(SRC_FILES)
	@mkdir -p $(OUTPUT_DIR_X86)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_x86 -c $< -o $@
	$(LLVM_STRIP) -g $@

$(OUTPUT_DIR_ARM)/tollwing.bpf.o: $(ENTRYPOINT_SRC) $(SRC_FILES)
	@mkdir -p $(OUTPUT_DIR_ARM)
	$(CLANG) $(BPF_CFLAGS) -D__TARGET_ARCH_arm64 -c $< -o $@
	$(LLVM_STRIP) -g $@

bpf-clean:
	@rm -f $(OUTPUTS)
