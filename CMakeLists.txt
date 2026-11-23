cmake_minimum_required(VERSION 3.25)
project(plutonium_devirt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(pdv_common STATIC
    src/common/aplib.cpp
    src/common/image.cpp
    src/common/pe.cpp
    src/common/sha256.cpp)
target_include_directories(pdv_common PUBLIC src/common)

if(MSVC)
    target_compile_options(pdv_common PUBLIC /W4 /permissive- /utf-8)
    target_compile_definitions(pdv_common PUBLIC _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(pdv_common PUBLIC -Wall -Wextra)
endif()

foreach(poc integrity_hash vjcc_vmd main_prefix handler_stats)
    add_executable(${poc} pocs/${poc}.cpp)
    target_link_libraries(${poc} PRIVATE pdv_common)
    target_compile_definitions(${poc} PRIVATE PDV_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
endforeach()
