# ==========================================================================
# Makefile for EL-DPI GUI application
#   • Default build: native e2k with lxx (C++)
#   • Alternative build: x86/amd64 with g++ via targets «x86» or «gcc»
# ==========================================================================

# ---------------------------- Architecture ---------------------------------
ARCH ?= e2k                # e2k (default) | x86

ifeq ($(ARCH),e2k)
	CXX ?= lxx
	ARCH_CXXFLAGS  := -m64 -me2k -mvliw -vectorize
	ARCH_LDFLAGS   :=
else
	CXX ?= g++
	ARCH_CXXFLAGS  :=
	ARCH_LDFLAGS   :=
endif

export ARCH CXX            # propagate to sub-makes

# ------------------------------ Flags --------------------------------------
QT_CFLAGS := $(shell pkg-config --cflags Qt5Widgets Qt5Sql)
QT_LIBS   := $(shell pkg-config --libs   Qt5Widgets Qt5Sql)

CXXFLAGS_COMMON := -Wall -Iinclude -I../core/include $(QT_CFLAGS) -fPIC
CXXFLAGS_OPT    ?= -O2
CXXFLAGS        ?= $(CXXFLAGS_OPT) $(CXXFLAGS_COMMON) $(ARCH_CXXFLAGS)

LDFLAGS_COMMON ?= $(QT_LIBS)
LDFLAGS        ?= $(LDFLAGS_COMMON) $(ARCH_LDFLAGS)

LDLIBS_BASE := -lpcap -lndpi -lsqlite3 -pthread

# ----------------------- DATA_DIR injection --------------------------------
ifeq ($(origin DATA_DIR), command line)
	DATAFLAG += DATA_DIR=\"$(DATA_DIR)\"
	CXXFLAGS += -DDATA_DIR=\"$(DATA_DIR)\"
else
	DATAFLAG :=
endif

# -------------------------- Debug settings ---------------------------------
SANITIZE_FLAGS := -fsanitize=address,undefined
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong \
                 -fno-strict-aliasing -DDEBUG

BUILD ?= release           # release | debug

ifeq ($(BUILD),debug)
	CXXFLAGS := $(filter-out -O%,$(CXXFLAGS_COMMON)) $(DEBUG_FLAGS) $(ARCH_CXXFLAGS)
	LDFLAGS  := $(LDFLAGS_COMMON) $(SANITIZE_FLAGS) $(ARCH_LDFLAGS)
	OBJDIR   := obj/debug
	TARGET   := ELDPI_debug
	LIBCORE  := ../core/libeldpi_debug.a
else
	OBJDIR   := obj
	TARGET   := ELDPI
	LIBCORE  := ../core/libeldpi.a
endif

LDLIBS := $(LIBCORE) $(LDLIBS_BASE)

# ------------------------------ Sources ------------------------------------
SRCDIR := src
INCDIR := include
SRC    := $(wildcard $(SRCDIR)/*.cpp)
OBJ    := $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRC))

MOC_HEADERS := $(wildcard $(INCDIR)/*.h)
MOC_CPP     := $(patsubst $(INCDIR)/%.h,$(OBJDIR)/moc_%.cpp,$(MOC_HEADERS))
MOC_OBJ     := $(patsubst %.cpp,%.o,$(MOC_CPP))

# ------------------------------ Targets ------------------------------------
.PHONY: all x86 gcc debug clean

all: $(TARGET)

# --- Architecture aliases ---------------------------------------------------
ALIAS_FILTERED_GOALS := $(filter-out x86 gcc,$(MAKECMDGOALS))

x86 gcc:
	$(MAKE) ARCH=x86 CXX=g++ $(if $(ALIAS_FILTERED_GOALS),$(ALIAS_FILTERED_GOALS),all)

# Debug wrapper
debug:
	$(MAKE) BUILD=debug

# Main executable
$(TARGET): $(LIBCORE) $(OBJ) $(MOC_OBJ)
	$(CXX) $(OBJ) $(MOC_OBJ) $(LDFLAGS) $(LDLIBS) -o $@

# Compile sources
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile MOC-generated sources
$(OBJDIR)/moc_%.o: $(OBJDIR)/moc_%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate MOC cpp files
$(OBJDIR)/moc_%.cpp: $(INCDIR)/%.h | $(OBJDIR)
	moc $< -o $@

# Ensure object directory exists
$(OBJDIR):
	@mkdir -p $@

# Build core library if missing or outdated
$(LIBCORE):
	$(MAKE) -C ../core ARCH=$(ARCH) CC=$(if $(findstring x86,$(ARCH)),gcc,lcc) BUILD=$(BUILD) $(DATAFLAG)

# Clean
clean:
	rm -rf obj obj/debug ELDPI ELDPI_debug
