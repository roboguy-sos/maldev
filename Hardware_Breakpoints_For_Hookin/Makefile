CXX      = clang++ --target=x86_64-w64-windows-gnu
CXXFLAGS = -std=c++17 -O0 -g -gcodeview -Wall -Wextra
LDFLAGS  = -static -fuse-ld=lld -Wl,--pdb=build/main.pdb
TARGET   = build/main.exe
SRC      = src/main.cpp
OBJ      = build/main.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

build/main.o: $(SRC) | build
	$(CXX) $(CXXFLAGS) -c $< -o $@

build:
	mkdir -p $@

clean:
	rm -rf build
