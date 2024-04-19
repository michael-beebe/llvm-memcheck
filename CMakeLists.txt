

# --- Add Clang libraries
find_package(Clang REQUIRED)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")


# --- Add the memcheck Static Library
add_library(StaticMemCheck MODULE staticMemCheck.cpp)
target_compile_options(StaticMemCheck PRIVATE -fno-rtti)
set_target_properties(
  StaticMemCheck PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

include_directories(${CLANG_INCLUDE_DIRS})
link_directories(${CLANG_LIBRARY_DIRS})
add_definitions(${CLANG_DEFINITIONS})

