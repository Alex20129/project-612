cmake_minimum_required(VERSION 2.8)

file(GLOB JANSSON_LIB_SRC "*.h" "*.c")

add_library(jansson ${JANSSON_LIB_SRC})
