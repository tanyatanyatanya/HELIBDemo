cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(HELIBDemo VERSION 1.0) 
add_executable(helibdemo_millionaire helibdemo_millionaire.cpp) 
add_executable(helibdemo_performance helibdemo_performance.cpp) 

find_package(helib)
target_link_libraries(helibdemo_millionaire helib)
target_link_libraries(helibdemo_performance helib)
