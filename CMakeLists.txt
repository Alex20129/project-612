cmake_minimum_required(VERSION 3.0)

PROJECT(project-612)
SET(CMAKE_CXX_FLAGS "-Wall -O2")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/jansson-2.9")
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/jansson-2.9")
LINK_LIBRARIES(jansson doublefann)

ADD_EXECUTABLE(${PROJECT_NAME} "project-612.hpp" "project-612.cpp")
