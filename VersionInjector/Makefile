CXX_SOURCES=VersionInjector.cpp
OBJ=$(CXX_SOURCES:.cpp=_dbg$(DBG).o)

STATIC_LINK_LIBS=-static-libgcc -static-libstdc++

.PHONY: all $(OUTPUT) ../src/$(VER_INJECT_LIB) clean

all: $(OUTPUT)

../src/$(VER_INJECT_LIB):
	$(MAKE) -C ../src $(VER_INJECT_LIB) VER_INJECT_LIB=$(VER_INJECT_LIB)

%_dbg$(DBG).o: %.cpp
	$(CXX) -c -o $@ $(CXXFLAGS) $<

$(OUTPUT): $(OBJ) ../src/$(VER_INJECT_LIB)
	$(CXX) $(LDFLAGS) -o "$@" $(LDFLAGS) $^ -lcomdlg32 $(STATIC_LINK_LIBS)

clean:
	rm -f *.o
