CXX ?= g++

CXXFLAGS_BASE := -Wall -Iinclude -I../core/include $(shell pkg-config --cflags Qt5Widgets Qt5Sql) -fPIC
CXXFLAGS_OPT ?= -O2
CXXFLAGS ?= $(CXXFLAGS_OPT) $(CXXFLAGS_BASE)

LDFLAGS ?= $(shell pkg-config --libs Qt5Widgets Qt5Sql)
	
SANITIZE_FLAGS := -fsanitize=address,undefined
DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong -fno-strict-aliasing -DDEBUG

BUILD ?= release

ifneq ($(filter debug,$(MAKECMDGOALS)),)
  BUILD := debug
endif

ifeq ($(BUILD),debug)
  CXXFLAGS := $(filter-out -O%,$(CXXFLAGS_BASE)) $(DEBUG_FLAGS) $(shell pkg-config --cflags Qt5Widgets Qt5Sql) -fPIC
  LDFLAGS += $(SANITIZE_FLAGS)
  OBJDIR := obj/debug
  TARGET := ELDPI_debug
  LIBCORE := ../core/libeldpi_debug.a
  LDLIBS := ../core/libeldpi_debug.a -lpcap -lndpi -lsqlite3 -pthread
else
  OBJDIR := obj
  TARGET := ELDPI
  LIBCORE := ../core/libeldpi.a
  LDLIBS := ../core/libeldpi.a -lpcap -lndpi -lsqlite3 -pthread
endif

ifeq ($(origin DATA_DIR), command line)
  DATAFLAG += DATA_DIR=\"$(DATA_DIR)\"
else
  DATAFLAG :=
endif

SRCDIR := src
INCDIR := include
SRC := $(wildcard $(SRCDIR)/*.cpp)
OBJ := $(patsubst $(SRCDIR)/%.cpp,$(OBJDIR)/%.o,$(SRC))
MOC_HEADERS := $(wildcard $(INCDIR)/*.h)
MOC_CPP := $(patsubst $(INCDIR)/%.h,$(OBJDIR)/moc_%.cpp,$(MOC_HEADERS))
MOC_OBJ := $(patsubst %.cpp,%.o,$(MOC_CPP))

.PHONY: all debug clean

all: $(TARGET)

$(TARGET): $(LIBCORE) $(OBJ) $(MOC_OBJ)
	$(CXX) $(OBJ) $(MOC_OBJ) $(LDLIBS) $(LDFLAGS) -o $@


$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/moc_%.o: $(OBJDIR)/moc_%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/moc_%.cpp: $(INCDIR)/%.h
	@mkdir -p $(OBJDIR)
	moc $< -o $@

$(LIBCORE):
	$(MAKE) -C ../core BUILD=$(BUILD) $(DATAFLAG)

debug: all

clean:
	rm -rf obj ELDPI ELDPI_debug

