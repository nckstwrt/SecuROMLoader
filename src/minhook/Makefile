.PHONY: all clean

SOURCES=$(wildcard *.cpp) $(wildcard hde/*.cpp)
OBJ = $(SOURCES:.cpp=_dbg$(DBG).o)

all: $(ARCHIV)

%_dbg$(DBG).o: %.cpp
	$(CXX) -c -o $@ $(CXXFLAGS) $<

$(ARCHIV): ${OBJ}
	$(AR) rc $@ $(OBJ)

clean:
	rm -f *.a *.o hde/*.o
