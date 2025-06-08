CXX ?= g++

CXXFLAGS_BASE := -Wall -Iinclude -I../core/include $(shell pkg-config --cflags Qt5Widgets Qt5Sql) -fPIC
CXXFLAGS_OPT ?= -O2
	CXXFLAGS ?= $(CXXFLAGS_OPT) $(CXXFLAGS_BASE)

LDFLAGS ?= $(shell pkg-config --libs Qt5Widgets Qt5Sql)
	LDLIBS ?= ../core/libeldpi.a -lpcap -lndpi -lsqlite3 -pthread
	
			SANITIZE_FLAGS := -fsanitize=address,undefined
	DEBUG_FLAGS    := -O0 -g3 -ggdb -fno-omit-frame-pointer -fstack-protector-strong -fno-strict-aliasing -DDEBUG

	BUILD ?= release
		ifeq ($(BUILD),debug)
	  CXXFLAGS := $(filter-out -O%,$(CXXFLAGS_BASE)) $(DEBUG_FLAGS) $(shell pkg-config --cflags Qt5Widgets Qt5Sql) -fPIC
	  LDFLAGS += $(SANITIZE_FLAGS)
  OBJDIR := obj/debug
		  TARGET := ELDPI-GUI_debug
  LIBCORE := ../core/libeldpi_debug.a
	else
	  OBJDIR ?= obj
		  TARGET ?= ELDPI-GUI
  LIBCORE := ../core/libeldpi.a
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
	$(MAKE) -C ../core BUILD=$(BUILD)

debug:
	$(MAKE) BUILD=debug

clean:
	rm -rf obj ELDPI-GUI ELDPI-GUI_debug

