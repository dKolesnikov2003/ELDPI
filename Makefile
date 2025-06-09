BUILD ?= release          # или debug
# Подставляем постфикс _debug для debug-режима
ifeq ($(BUILD),debug)
  SUFFIX := _debug
else
  SUFFIX :=
endif

ifeq ($(origin DATA_DIR), command line)
  DATAFLAG := DATA_DIR=$(DATA_DIR) 
else
  DATAFLAG := DATA_DIR=/usr/local/share/ELDPI
endif
BINDIR ?= /usr/local/bin/ELDPI 

SUBDIRS := core cli gui

.PHONY: all debug clean install uninstall $(SUBDIRS)

all: core/libeldpi$(SUFFIX).a cli/ELDPI-CLI$(SUFFIX) gui/ELDPI$(SUFFIX)

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

install: all
	@echo ">> Установка в каталог $(BINDIR)"
	install -d $(BINDIR)
	install -m 755 cli/ELDPI-CLI$ $(BINDIR)/ELDPI-CLI$
	install -m 755 gui/ELDPI$  $(BINDIR)/ELDPI$

	@echo ">> Назначение прав"
	if command -v setcap >/dev/null; then \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI$; \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI-CLI$; \
	else \
	  echo "!! Утилита setcap не найдена — при необходимости назначьте права вручную."; \
	fi

	@echo ">> Установка завершена."

uninstall:                   
	@echo ">> Удаление из $(BINDIR)"
	@rm -f $(BINDIR)/ELDPI$(SUFFIX) $(BINDIR)/ELDPI-CLI$(SUFFIX) $(DATA_DIR)
	@echo ">> Удаление завершено."