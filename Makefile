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
  DATAFLAG :=
endif

SUBDIRS := core cli gui

.PHONY: all debug clean $(SUBDIRS)

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