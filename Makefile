# ==========================================================================
# Top‑level Makefile for EL‑DPI project
#   • Default architecture: e2k (Elbrus)
#   • Alternative architecture: x86/amd64 via targets «x86» or «gcc»
# ==========================================================================

# --------------------------- Architecture ----------------------------------
ARCH ?= e2k              # e2k (default) | x86

# Export ARCH so that sub‑directories inherit it automatically
export ARCH

# ---------------------------- Build type -----------------------------------
BUILD ?= release         # release | debug
SUFFIX :=
ifeq ($(BUILD),debug)
  SUFFIX := _debug       # attach postfix to built binaries/libs
endif

# ------------------------ Data directory handling --------------------------
ifeq ($(origin DATA_DIR), command line)
  DATA_DIR := $(DATA_DIR)
else
  DATA_DIR := /usr/local/share/ELDPI
endif
DATAFLAG := DATA_DIR=$(DATA_DIR)

# ----------------------------- Prefixes ------------------------------------
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

SUBDIRS := core cli gui

# ----------------------------- Phony ---------------------------------------
.PHONY: all x86 gcc debug clean install uninstall $(SUBDIRS)

# ---------------------------- Default target -------------------------------
all: core/libeldpi$(SUFFIX).a \
     cli/ELDPI-CLI$(SUFFIX)   \
     gui/ELDPI$(SUFFIX)

# --------------------- Build rules for sub‑projects ------------------------
core/libeldpi$(SUFFIX).a:
	$(MAKE) -C core BUILD=$(BUILD) $(DATAFLAG)

cli/ELDPI-CLI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C cli BUILD=$(BUILD) $(DATAFLAG)

gui/ELDPI$(SUFFIX): core/libeldpi$(SUFFIX).a
	$(MAKE) -C gui BUILD=$(BUILD) $(DATAFLAG)

# ---------------------- Architecture aliases -------------------------------
# Filter out alias targets themselves to avoid infinite recursion
ALIAS_FILTERED_GOALS := $(filter-out x86 gcc,$(MAKECMDGOALS))

x86 gcc:
	$(MAKE) ARCH=x86 $(if $(ALIAS_FILTERED_GOALS),$(ALIAS_FILTERED_GOALS),all)

# ------------------------------ Debug --------------------------------------
debug:
	$(MAKE) BUILD=debug $(DATAFLAG)

# ------------------------------ Clean --------------------------------------
clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done

# ----------------------------- Install -------------------------------------
install: all
	@echo ">> Installing to $(BINDIR)"
	install -d $(BINDIR)
	install -d -m 777 $(DATA_DIR)
	install -m 755 cli/ELDPI-CLI $(BINDIR)/ELDPI-CLI
	install -m 755 gui/ELDPI $(BINDIR)/ELDPI

	@echo ">> Setting capabilities (setcap)"
	@if command -v setcap >/dev/null; then \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI      ; \
	  sudo setcap cap_net_raw,cap_net_admin=eip $(BINDIR)/ELDPI-CLI ; \
	else \
	  echo "!! setcap not found — set capabilities manually if required."; \
	fi
	@echo ">> Installation completed."

# ---------------------------- Uninstall ------------------------------------
uninstall:
	@echo ">> Removing from $(BINDIR) and $(DATA_DIR)"
	rm -f  $(BINDIR)/ELDPI $(BINDIR)/ELDPI-CLI
	rm -rf $(DATA_DIR)
	@echo ">> Uninstall completed."
