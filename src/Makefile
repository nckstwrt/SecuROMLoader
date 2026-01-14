LIB_MINHOOK=minhook/minhook_dbg$(DBG).a

C_SOURCES=$(wildcard *.c)
CXX_SOURCES=$(wildcard *.cpp)
VER_INJCT_CXX_SOURCES=Config.cpp Utils.cpp
VER_INJCT_C_SOURCES=tiny-json.c

OBJ = $(CXX_SOURCES:.cpp=_dbg$(DBG).o) $(C_SOURCES:.c=_dbg$(DBG).o)
VER_INJCT_OBJ = $(VER_INJCT_CXX_SOURCES:.cpp=_dbg$(DBG).o) $(VER_INJCT_C_SOURCES:.c=_dbg$(DBG).o)

STATIC_LINK_LIBS=-static-libgcc -static-libstdc++


.PHONY: all $(LIB_MINHOOK) clean

all:

$(LIB_MINHOOK):
	$(MAKE) -C $(dir $(LIB_MINHOOK)) ARCHIV=$(notdir $(LIB_MINHOOK))

%_dbg$(DBG).o: %.c
	$(CC) -c -o $@ $(CFLAGS) $<

%_dbg$(DBG).o: %.cpp
	$(CXX) -c -o $@ $(CXXFLAGS) $<

$(VER_INJECT_LIB): $(VER_INJCT_OBJ)
	$(AR) rc $@ $^

$(OUTPUT_DLL): $(OBJ) $(LIB_MINHOOK) version.def
	$(CXX) $(LDFLAGS) -o "$@" -shared $^ $(STATIC_LINK_LIBS)

clean:
	rm -f *.o *.a
	$(MAKE) -C minhook clean
