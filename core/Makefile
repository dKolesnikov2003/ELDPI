# ==========================================================================
# Makefile for EL‑DPI core library
#   • Default: native e2k build with lcc
#   • Optional: x86/amd64 build with gcc via target «x86» (alias «gcc»)
# ==========================================================================

# ---------------------------- Architecture --------------------------------
ARCH ?= e2k              # e2k (default) | x86

ifeq ($(ARCH),e2k)
	CC ?= lcc
	ARCH_CFLAGS  := -m64 -me2k -mvliw -vectorize
	ARCH_LDFLAGS :=
else
	CC ?= gcc
	ARCH_CFLAGS  :=
	ARCH_LDFLAGS :=
endif

export ARCH CC           # propagate to sub‑makes

# ----------------------------- Flags --------------------------------------
CFLAGS_COMMON := -Wall -pthread -Iinclude
CFLAGS_OPT    ?= -O2
CFLAGS        ?= $(CFLAGS_OPT) $(CFLAGS_COMMON) $(ARCH_CFLAGS)

LDFLAGS_COMMON ?= -pthread
LDFLAGS        ?= $(LDFLAGS_COMMON) $(ARCH_LDFLAGS)

LDLIBS ?= -lpcap -lndpi -lsqlite3

# Inject DATA_DIR if provided from command line
ifeq ($(origin DATA_DIR), command line)
	CFLAGS += -DDATA_DIR=\"$(DATA_DIR)\"
endif

# ------------------------- Debug configuration ----------------------------
SANITIZE_FLAGS := -fsanitize=address,undefined
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer \
                 -fstack-protector-strong -fno-strict-aliasing -DDEBUG

BUILD ?= release        # release | debug

ifeq ($(BUILD),debug)
	CFLAGS  := $(filter-out -O%,$(CFLAGS_COMMON)) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) $(ARCH_CFLAGS)
	LDFLAGS := $(LDFLAGS_COMMON) $(SANITIZE_FLAGS) $(ARCH_LDFLAGS)
	OBJDIR  := obj/debug
else
	OBJDIR  := obj
endif

# --------------------------- Directories ----------------------------------
SRCDIR := src
TARGET := libeldpi.a     # common name for all architectures

SRC := $(wildcard $(SRCDIR)/*.c)
OBJ := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# --------------------------- Phony targets --------------------------------
.PHONY: all x86 gcc debug clean

all: $(TARGET)

# --- architecture aliases --------------------------------------------------
ALIAS_FILTERED_GOALS := $(filter-out x86 gcc,$(MAKECMDGOALS))

x86 gcc:
	$(MAKE) ARCH=x86 CC=gcc $(if $(ALIAS_FILTERED_GOALS),$(ALIAS_FILTERED_GOALS),all)

# --- debug build -----------------------------------------------------------
debug:
	$(MAKE) BUILD=debug

# --- build static library --------------------------------------------------
$(TARGET): $(OBJ)
	@mkdir -p /var/lib/eldpi/
	$(AR) rcs $@ $^

# --- compile objects -------------------------------------------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	@mkdir -p $@

# --- cleanup ---------------------------------------------------------------
clean:
	rm -rf obj $(TARGET) obj/debug libeldpi_debug.a
