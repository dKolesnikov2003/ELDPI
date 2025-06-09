BUILD ?= release          # или debug
# Подставляем постфикс _debug для debug-режима
ifeq ($(BUILD),debug)
  SUFFIX := _debug
else
  SUFFIX :=
endif

SUBDIRS := core cli gui

.PHONY: all debug clean $(SUBDIRS)

all: core/libeldpi$(SUFFIX).a cli/ELDPI-CLI$(SUFFIX) gui/ELDPI$(SUFFIX)

core/libeldpi$(SUFFIX).a:
	$(MAKE) -C core BUILD=$(BUILD)

cli/ELDPI-CLI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C cli BUILD=$(BUILD)

gui/ELDPI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C gui BUILD=$(BUILD)

debug:
	$(MAKE) BUILD=debug

clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done