DLL_FILE=version.dll
VER_INJECT_FILE=injector.exe

RELEASE_DIR=Release
DEBUG_DIR=Debug
VER_INJECT_DIR=VersionInjector


ERROR_LIMIT=1
TOOL_PREFIX=i686-w64-mingw32-
CC=$(TOOL_PREFIX)gcc-win32
CXX=$(TOOL_PREFIX)g++-win32
AR=$(TOOL_PREFIX)ar
CFLAGS=-fmax-errors=$(ERROR_LIMIT) -masm=intel -std=c11
CXXFLAGS=-fpermissive -fmax-errors=$(ERROR_LIMIT) -std=c++17

# use same asm syntax as MSCV
CFLAGS+=-masm=intel
CXXFLAGS+=-masm=intel

VER_INJECT_LIB=version_inject_dbg$(DBG).a

DEBUG?=0
ifeq ($(DEBUG), 0)
    DBG=0
    OUT_DIR=$(RELEASE_DIR)
    CFLAGS+=-O2
    CXXFLAGS+=-O2
	LDFLAGS=-s
else
	DBG=1
    OUT_DIR=$(DEBUG_DIR)
    CFLAGS+=-g -O0 -D_DEBUG
    CXXFLAGS+=-g -O0 -D_DEBUG
endif


export CC CFLAGS CXX CXXFLAGS LDFLAGS AR DBG


OUTPUT_DLL=$(OUT_DIR)/$(DLL_FILE)
OUTPUT_VER_INJECT=$(OUT_DIR)/$(VER_INJECT_FILE)

.PHONY: all $(OUTPUT_DLL) $(OUTPUT_VER_INJECT) dll injector clean help


all: $(OUTPUT_DLL) $(OUTPUT_VER_INJECT)

help:
	@echo "$(MAKE) \t\tbuild $(DLL_FILE) + $(VER_INJECT_FILE)"
	@echo "$(MAKE) dll\tbuild $(DLL_FILE)"
	@echo "$(MAKE) injector\tbuild $(VER_INJECT_FILE)"
	@echo "$(MAKE) clean\tfor cleanup"
	@echo "$(MAKE) DEBUG=1\tfor debug build"
	@echo "\nDefault output dir: $(RELEASE_DIR), for debug builds: $(DEBUG_DIR)"
	@echo "Dependencies (Ubuntu): make g++-mingw-w64-i686-win32"

dll: $(OUTPUT_DLL)

injector: $(OUTPUT_VER_INJECT)



$(OUTPUT_VER_INJECT):
	$(MAKE) -C $(VER_INJECT_DIR) OUTPUT="../$(OUTPUT_VER_INJECT)" "VER_INJECT_LIB=$(VER_INJECT_LIB)"

$(OUTPUT_DLL):
	test -d "$(OUT_DIR)" || mkdir "$(OUT_DIR)"
	$(MAKE) -C src OUTPUT_DLL="../$(OUTPUT_DLL)" VER_INJECT_LIB="$(VER_INJECT_LIB)" "../$(OUTPUT_DLL)"

clean:
	rm -fr $(RELEASE_DIR)/* $(DEBUG_DIR)/*
	$(MAKE) -C src clean
	$(MAKE) -C $(VER_INJECT_DIR) clean
