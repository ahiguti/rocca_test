
all: rocca rocca_dbg

CXX = g++ --std=c++11 -Wno-ignored-attributes

CXXFLAGS = -g -Wall -O3 -DNDEBUG -finline-functions -funroll-loops
CXXDBGFLAGS = -g -Wall -DDEBUG

rocca: rocca.cc
	$(CXX) $(CXXFLAGS) -march=native $^ -o $@

rocca_dbg: rocca.cc
	$(CXX) $(CXXDBGFLAGS) -march=native $^ -o $@

clean:
	rm -rf rocca rocca_dbg *.dSYM

