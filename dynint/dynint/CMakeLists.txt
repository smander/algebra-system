cmake_minimum_required(VERSION 3.10)
project(dynint_wrapper)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required libraries
find_package(Boost REQUIRED COMPONENTS system filesystem)
find_package(Threads REQUIRED)

# Include directories for built DynInst
include_directories(/usr/local/include)
include_directories(/usr/local/include/dyninst)

# Library directories
link_directories(/usr/local/lib)

# Add executable
add_executable(dyninst_wrapper dyninst_wrapper.cpp)

# Link libraries (manually specify DynInst libraries)
target_link_libraries(dyninst_wrapper
    dyninstAPI
    parseAPI
    instructionAPI
    symtabAPI
    dynElf
    dynDwarf
    common
    ${Boost_LIBRARIES}
    Threads::Threads
    dl
    elf
    dwarf
    iberty
)

# Set runtime library path
set_target_properties(dyninst_wrapper PROPERTIES
    INSTALL_RPATH "/usr/local/lib"
    BUILD_WITH_INSTALL_RPATH TRUE
)