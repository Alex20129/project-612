cmake_minimum_required(VERSION 2.8)

file(GLOB SQLITE_LIB_SRC "*.h" "*.c")

add_library(sqlite ${SQLITE_LIB_SRC})
