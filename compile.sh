#!/bin/bash

# ---- Create the build dir, clean it
rm -rf build .cache
mkdir -p build
cd build

# ---- Set desired compilers
export CC="`which clang`"
export CXX="`which clang++`"

export CXXFLAGS="-I$LLVM_INCLUDE"
export LDFLAGS="-L$LLVM_LIB/x86_64-unknown-linux-gnu" # -Wl,-rpath,$LLVM_LIB/x86_64-unknown-linux-gnu"

# ---- Build the project
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=YES ..
make VERBOSE=1
