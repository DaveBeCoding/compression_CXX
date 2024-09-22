cmake_minimum_required(VERSION 3.10)
project(FileCompressionExample)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find and link Zlib (compression library)
find_package(ZLIB REQUIRED)

# Add the executable file for your main program
add_executable(FileCompressionExample main.cxx)

# Link the Zlib library with your executable
target_link_libraries(FileCompressionExample ZLIB::ZLIB)
