# Specify the minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Set the project name and the C++ standard
project(CreateRandomFile)

# Set the C++ standard to C++11 or later
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable using the correct source file name
add_executable(create_random_file createF.cxx)
