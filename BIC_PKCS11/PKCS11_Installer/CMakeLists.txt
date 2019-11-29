cmake_minimum_required(VERSION 3.5)

project(BlackICE_Connect_Installer C)

set(PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

## COLORS ##
if(${shell_color}) # They will only work in CLI (thus, it won't show encoded message in VS build console)
    string(ASCII 27 Esc)
    set(RESETCOLOR  "${Esc}[m")
    set(BOLDCOLOR   "${Esc}[1m")
    set(RED         "${Esc}[31m")
    set(GREEN       "${Esc}[32m")
    set(YELLOW      "${Esc}[33m")
    set(BLUE        "${Esc}[34m")
    set(MAGENTA     "${Esc}[35m")
    set(CYAN        "${Esc}[36m")
    set(WHITE       "${Esc}[37m")
    set(BOLDRED     "${Esc}[1;31m")
    set(BOLDGREEN   "${Esc}[1;32m")
    set(BOLDYELLOW  "${Esc}[1;33m")
    set(BOLDBLUE    "${Esc}[1;34m")
    set(BOLDMAGENTA "${Esc}[1;35m")
    set(BOLDCYAN    "${Esc}[1;36m")
    set(BOLDWHITE   "${Esc}[1;37m")
endif()

## CURRENT PLATFORM ##
if((${arch} MATCHES "x86") OR (CMAKE_SIZEOF_VOID_P EQUAL 4))
    set(TARGET_PLATFORM 86)
elseif((${arch} MATCHES "x64") OR CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TARGET_PLATFORM 64)
else()
    message("${RED} Neither architecture (${arch}) nor CMAKE_SIZEOF_VOID_P (${CMAKE_SIZEOF_VOID_P}) have a proper value ${RESETCOLOR}")
    return()
endif()

set(TARGET_NAME GradiantEncryptConfig_debug_x${TARGET_PLATFORM})

set(CMAKE_VERBOSE_MAKEFILE ON)

## CURRENT OS ##
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(TARGET_SYSTEM linux)
else()
    message("${BOLDRED}Cancelling compilation because target system is not a Linux machine${RESETCOLOR}")
    return()
endif()

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE)

string(REPLACE "debug" "${BUILD_TYPE}" TARGET_NAME "${TARGET_NAME}")

message("Build configuration: " ${TARGET_SYSTEM} "-" ${TARGET_PLATFORM} "-" ${BUILD_TYPE})
message("Build name: " ${TARGET_NAME})

## COMPILER-LINKER FLAGS ##
# Generic flags for all build configurations
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wimplicit-function-declaration -Wstrict-prototypes -Wmissing-prototypes -Wfatal-errors -fstack-protector-all -Wl,-z,noexecstack")# -Wall")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g3 -ggdb -O0 -rdynamic")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} ")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fPIC -Wl,--no-undefined")

## EXECUTABLE BUILDING ##
# TODO: If we want to build VS project from CMake at some point, we need to pass those PreprocessorDefinitions in order to match VS configuration: _DEBUG;_WINDOWS;_USRDLL;CS_PKCS11_R2_EXPORTS;CRYPTOKI_EXPORTS;_CRT_SECURE_NO_WARNINGS;CURL_STATICLIB;%(PreprocessorDefinitions)
#set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_DIR}/bin/${TARGET_SYSTEM}/${TARGET_PLATFORM})
add_executable(${TARGET_NAME} "")

set_target_properties(${TARGET_NAME}
    PROPERTIES
    LINKER_LANGUAGE C
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_DIR}/bin/${TARGET_SYSTEM}-${BUILD_TYPE}/x${TARGET_PLATFORM}"
)

if(${TARGET_PLATFORM} MATCHES "86")
    set_target_properties(${TARGET_NAME}
        PROPERTIES
        COMPILE_FLAGS "-m32"
        LINK_FLAGS "-m32"
    )
endif()

## SOURCES ##
target_sources(${TARGET_NAME}
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/PKCS11_Interface.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/PKCS11_Interface.c"
        "${CMAKE_CURRENT_SOURCE_DIR}/PKCS11_Installer.c"
)

target_link_libraries(${TARGET_NAME} PRIVATE ${CMAKE_DL_LIBS})
message("${BOLDGREEN}Linked${RESETCOLOR} m (math lib)")
