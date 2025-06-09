# ------------------------- Makefile (fixed) -------------------------
# 1. Тип сборки ─ release|debug
BUILD ?= release
ifeq ($(BUILD),debug)
  SUFFIX := _debug          # бинарям добавляем постфикс _debug
else
  SUFFIX :=
endif

# 2. Куда положить данные (можно переопределить "make DATA_DIR=..."):
ifeq ($(origin DATA_DIR), command line)
  DATA_DIR := $(DATA_DIR)
else
  DATA_DIR := /usr/local/share/ELDPI
endif
DATAFLAG := DATA_DIR=$(DATA_DIR)

# 3. Каталог для бинарей (можно переопределить "make BINDIR=..."):
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

SUBDIRS := core cli gui

.PHONY: all debug clean install uninstall $(SUBDIRS)

# --------------------------------------------------------------------
	#  пост-условия
	all: core/libeldpi$(SUFFIX).a \
    cli/ELDPI-CLI$(SUFFIX) \
    gui/ELDPI$(SUFFIX)

core/libeldpi$(SUFFIX).a:
	$(MAKE) -C core BUILD=$(BUILD) $(DATAFLAG)

cli/ELDPI-CLI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C cli BUILD=$(BUILD) $(DATAFLAG)

gui/ELDPI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C gui BUILD=$(BUILD) $(DATAFLAG)

debug:
	$(MAKE) BUILD=debug $(DATAFLAG)

clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

# --------------------------------------------------------------------
#  установка
install: all
	@echo ">> Установка в $(BINDIR)"
	install -d  $(BINDIR)
	install -d -m 777 $(DATA_DIR)
	install -m 755 cli/ELDPI-CLI $(BINDIR)/ELDPI-CLI
	install -m 755 gui/ELDPI $(BINDIR)/ELDPI

	@echo ">> Назначение прав (setcap)"
	if command -v setcap >/dev/null; then \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI	; \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI-CLI; \
	else \
	  echo "!! setcap не найден — назначьте права вручную, если нужно."; \
	fi
	@echo ">> Установка завершена."

# --------------------------------------------------------------------
#  удаление
uninstall:
	@echo ">> Удаление из $(BINDIR) и $(DATA_DIR)"
	rm -f  $(BINDIR)/ELDPI $(BINDIR)/ELDPI-CLI
	rm -rf $(DATA_DIR)
	@echo ">> Удаление завершено."
# --------------------------------------------------------------------
