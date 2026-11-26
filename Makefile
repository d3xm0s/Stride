CXX = x86_64-w64-mingw32-g++
CXXFLAGS = -std=c++17 -O2 -static -static-libgcc -static-libstdc++
LDLIBS = -lole32 -loleaut32 -luuid -lwbemuuid -lmpr

stride.exe: stride.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f stride.exe
