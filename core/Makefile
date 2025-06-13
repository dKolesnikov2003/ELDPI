# ==========================================================================
# Makefile for EL‑DPI core library
#   • По умолчанию собирает нативный e2k‑код с помощью lcc
#   • Поддерживает альтернативную сборку под x86/amd64 (gcc) через цель «x86»
# ==========================================================================

# -------------------------- Архитектура и компилятор ------------------------
ARCH          ?= e2k          

# Компилятор по умолчанию для выбранной архитектуры
ifeq ($(ARCH),e2k)
  CC          ?= lcc
  ARCH_CFLAGS := -m64 -me2k -mvliw -vectorize
  ARCH_LDFLAGS:=
else
  CC          ?= gcc
  ARCH_CFLAGS :=               
  ARCH_LDFLAGS:=
endif

# --------------------------- Базовые флаги ---------------------------------
CFLAGS_COMMON := -Wall -pthread -Iinclude
CFLAGS_OPT    ?= -O2
CFLAGS        ?= $(CFLAGS_OPT) $(CFLAGS_COMMON) $(ARCH_CFLAGS)

LDFLAGS_COMMON?= -pthread
LDFLAGS       ?= $(LDFLAGS_COMMON) $(ARCH_LDFLAGS)

LDLIBS        ?= -lpcap -lndpi -lsqlite3

# Подстановка макроса DATA_DIR, если указан с командной строки
ifeq ($(origin DATA_DIR), command line)
  CFLAGS += -DDATA_DIR=\"$(DATA_DIR)\"
endif

# ----------------------- Флаги для режима отладки --------------------------
SANITIZE_FLAGS:= -fsanitize=address,undefined
DEBUG_FLAGS   := -O0 -g3 -ggdb -fno-omit-frame-pointer \
                 -fstack-protector-strong -fno-strict-aliasing -DDEBUG

BUILD ?= release               # release | debug

ifeq ($(BUILD),debug)
  CFLAGS := $(filter-out -O%,$(CFLAGS_COMMON)) $(DEBUG_FLAGS) $(SANITIZE_FLAGS) $(ARCH_CFLAGS)
  LDFLAGS := $(LDFLAGS_COMMON) $(SANITIZE_FLAGS) $(ARCH_LDFLAGS)
  OBJDIR := obj/debug
else
  OBJDIR := obj
endif

# ----------------------------- Пути и файлы --------------------------------
SRCDIR  := src
OBJDIR  := $(OBJDIR)
TARGET  := libeldpi.a          # название не меняется

SRC     := $(wildcard $(SRCDIR)/*.c)
OBJ     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# ------------------------------- Цели --------------------------------------
.PHONY: all x86 gcc debug clean

all: $(TARGET)

# Альтернативная сборка под x86 (gcc)
x86 gcc:
	$(MAKE) ARCH=x86 CC=gcc $(MAKECMDGOALS)

# Удобная обёртка для сборки debug
debug:
	$(MAKE) BUILD=debug

# Статическая библиотека
$(TARGET): $(OBJ)
	@mkdir -p /var/lib/eldpi/
	$(AR) rcs $@ $^

# Правило компиляции каждого исходного файла
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Создание каталога для объектных файлов
$(OBJDIR):
	@mkdir -p $@

# Очистка
clean:
	rm -rf obj $(TARGET) obj/debug libeldpi_debug.a
