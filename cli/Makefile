# ==========================================================================
# Makefile for EL-DPI CLI utility
#   • Default build: native e2k (lcc)
#   • Alternative build: x86/amd64 (gcc) via targets «x86» or «gcc»
# ==========================================================================

# --------------------------- Архитектура -----------------------------------
ARCH ?= e2k                # e2k (default) | x86

ifeq ($(ARCH),e2k)
	CC ?= lcc
	ARCH_CFLAGS  := -m64 -me2k -mvliw -vectorize
	ARCH_LDFLAGS :=
else
	CC ?= gcc
	ARCH_CFLAGS  :=
	ARCH_LDFLAGS :=
endif

export ARCH CC            

# ----------------------------- Флаги ---------------------------------------
CFLAGS_COMMON := -Wall -I../core/include
CFLAGS_OPT    ?= -O2
CFLAGS        ?= $(CFLAGS_OPT) $(CFLAGS_COMMON) $(ARCH_CFLAGS)

LDFLAGS_COMMON ?=
LDFLAGS        ?= $(LDFLAGS_COMMON) $(ARCH_LDFLAGS)

LDLIBS ?= -lpcap -lndpi -lsqlite3 -pthread

# Подстановка DATA_DIR (если передано)
ifeq ($(origin DATA_DIR), command line)
	DATAFLAG += DATA_DIR=\"$(DATA_DIR)\"
	CFLAGS   += -DDATA_DIR=\"$(DATA_DIR)\"
else
	DATAFLAG :=
endif

# ------------------------ Debug configuration -----------------------------
SANITIZE_FLAGS := -fsanitize=address,undefined
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong \
                 -fno-strict-aliasing -DDEBUG

BUILD ?= release           # release | debug

ifeq ($(BUILD),debug)
	CFLAGS  := $(filter-out -O%,$(CFLAGS_COMMON)) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) $(ARCH_CFLAGS)
	LDFLAGS := $(LDFLAGS_COMMON) $(SANITIZE_FLAGS) $(ARCH_LDFLAGS)
	OBJDIR  := obj/debug
	TARGET  := ELDPI-CLI_debug
	LIBCORE := ../core/libeldpi_debug.a
else
	OBJDIR  := obj
	TARGET  := ELDPI-CLI
	LIBCORE := ../core/libeldpi.a
endif

# --------------------------- Файлы ----------------------------------------
SRCDIR := src
SRC    := $(wildcard $(SRCDIR)/*.c)
OBJ    := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# --------------------------- Цели -----------------------------------------
.PHONY: all x86 gcc debug clean

all: $(TARGET)

# --- Архитектурные алиасы --------------------------------------------------
ALIAS_FILTERED_GOALS := $(filter-out x86 gcc,$(MAKECMDGOALS))

x86 gcc:
	$(MAKE) ARCH=x86 CC=gcc $(if $(ALIAS_FILTERED_GOALS),$(ALIAS_FILTERED_GOALS),all)

# --- Удобная сборка debug ---------------------------------------------------
debug:
	$(MAKE) BUILD=debug

# --- Основной исполняемый файл --------------------------------------------
$(TARGET): $(LIBCORE) $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBCORE) $(LDLIBS) -o $@

# --- Компиляция объектов ---------------------------------------------------
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	@mkdir -p $@

# --- Сборка библиотеки ядра (если требуется) -------------------------------
$(LIBCORE):
	$(MAKE) -C ../core ARCH=$(ARCH) CC=$(CC) BUILD=$(BUILD) $(DATAFLAG)

# --- Очистка ---------------------------------------------------------------
clean:
	rm -rf obj obj/debug ELDPI-CLI ELDPI-CLI_debug
