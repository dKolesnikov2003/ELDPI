# ------------------ Параметры компилятора ------------------
CC          ?= gcc

# базовые CFLAGS ─ те же, что в core, + путь к её заголовкам
CFLAGS_BASE := -Wall -I../core/include
CFLAGS_OPT  ?= -O2
CFLAGS      ?= $(CFLAGS_OPT) $(CFLAGS_BASE)

LDFLAGS_BASE ?=
LDFLAGS      ?= $(LDFLAGS_BASE)

LDLIBS ?= -lpcap -lndpi -lsqlite3 -pthread

# ------------------ Отладочный режим -----------------------
SANITIZE_FLAGS := -fsanitize=address,undefined
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong \
                  -fno-strict-aliasing -DDEBUG

BUILD ?= release      # release | debug

ifeq ($(BUILD),debug)
  CFLAGS   := $(filter-out -O%,$(CFLAGS_BASE)) $(DEBUG_FLAGS) $(SANITIZE_FLAGS)
  LDFLAGS  := $(LDFLAGS_BASE) $(SANITIZE_FLAGS)
  OBJDIR   := obj/debug
  TARGET   := ELDPI-CLI_debug
  LIBCORE  := ../core/libeldpi_debug.a
else
  OBJDIR ?= obj
  TARGET ?= ELDPI-CLI
  LIBCORE := ../core/libeldpi.a
endif

# ------------------ Пути и файлы ---------------------------
SRCDIR := src
SRC    := $(wildcard $(SRCDIR)/*.c)
OBJ    := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRC))

# ------------------ Цели ----------------------------------
.PHONY: all debug clean

all: $(TARGET)

# Основной исполняемый файл
$(TARGET): $(LIBCORE) $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LIBCORE) $(LDLIBS) -o $@

# Каждый объект
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Библиотека ядра как зависимость:
# если её нет (или устарела), сначала вызываем make в ../core
$(LIBCORE):
	$(MAKE) -C ../core BUILD=$(BUILD)

# Удобная обёртка для сборки debug-варианта
debug:
	$(MAKE) BUILD=debug

# Уборка
clean:
	rm -rf obj ELDPI-CLI ELDPI-CLI_debug
