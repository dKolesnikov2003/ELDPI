# Компилятор и флаги
CC      ?= gcc

# --- Общие флаги -------------------------------------------------------------
CFLAGS_BASE := -Wall -pthread -Iinclude
CFLAGS_OPT  ?= -O2
CFLAGS      ?= $(CFLAGS_OPT) $(CFLAGS_BASE)

LDFLAGS_BASE ?= -pthread
LDFLAGS      ?= $(LDFLAGS_BASE)

LDLIBS  ?= -lpcap -lndpi -lsqlite3

# --- Флаги для режима отладки ------------------------------------------------
SANITIZE_FLAGS := -fsanitize=address,undefined   # адресные, утечки, UBs
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong -fno-strict-aliasing -DDEBUG

# --- Конфигурация режима сборки ---------------------------------------------
#  * BUILD=release (по умолчанию)
#  * BUILD=debug   – с санитайзерами / полной отладочной информацией
BUILD ?= release

ifeq ($(BUILD),debug)
  CFLAGS := $(filter-out -O%,$(CFLAGS_BASE)) $(DEBUG_FLAGS) $(SANITIZE_FLAGS)
  LDFLAGS := $(LDFLAGS_BASE) $(SANITIZE_FLAGS)
  OBJDIR := obj/debug
  TARGET := libeldpi_debug.a
else
  OBJDIR ?= obj
  TARGET ?= libeldpi.a
endif

# --- Пути, файлы -------------------------------------------------------------
SRCDIR  := src
INCDIR  := include

SRC     := $(wildcard $(SRCDIR)/*.c)
OBJ     := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# --- Цели --------------------------------------------------------------------
.PHONY: all debug clean

# Сборка по умолчанию
all: $(TARGET)

# Удобная обёртка: make debug
debug:
	$(MAKE) BUILD=debug

# $(TARGET): $(OBJ)
# 	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(TARGET): $(OBJ)
	@mkdir -p /var/lib/eldpi/
	$(AR) rcs $@ $^

# Компиляция объектов
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Очистка
clean:
	rm -rf obj $(TARGET) libeldpi_debug.a
