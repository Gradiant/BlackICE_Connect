################################
#### CMAKE CONF & PARAMS
################################
cmake_minimum_required(VERSION 3.5)

project(BlackICE_Connect C) # Necessary before CMAKE_SIZEOF_VOID_P

set(CMAKE_VERBOSE_MAKEFILE ON)

string(TOLOWER ${CMAKE_BUILD_TYPE} BUILD_TYPE)

################################
#### SHELL COLOR SUPPORT
################################
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

################################
#### PLATFORM & ARCHITECTURE
################################

## PLATFORM ##
if(UNIX)
    set(TARGET_SYSTEM "linux")
else()
    #TODO: Add support for MSVC to generate VS project if desired.
    message("${BOLDRED}Platform is not Linux${RESETCOLOR}")
    return()
endif()

## ARCHITECTURE ##
if((${x86}) OR (CMAKE_SIZEOF_VOID_P EQUAL 4))
    set(TARGET_PLATFORM 86)
    set(PLATFORM_BITS 32)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(TARGET_PLATFORM 64)
    set(PLATFORM_BITS 64)
else()
    message("${BOLDRED}Can't detect architecture${RESETCOLOR}")
    return()
endif()

message("${BOLDYELLOW}Build configuration: " ${TARGET_SYSTEM} "-" ${TARGET_PLATFORM} "-" ${BUILD_TYPE} "${RESETCOLOR}")

################################
#### PROJECT
################################

set(TARGET_NAME BlackICEConnect_x${TARGET_PLATFORM})

set(PROJECT_DIR ${CMAKE_SOURCE_DIR})

# TODO: If building VS project is desired, preprocessor definitions like _DEBUG, _WINDOWS or _CRT_SECURE_NO_WARNINGS should be added to the target.
add_library(${TARGET_NAME} SHARED "")

set_target_properties(${TARGET_NAME}
    PROPERTIES
    LINKER_LANGUAGE C
    LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin/${TARGET_SYSTEM}-${BUILD_TYPE}/x${TARGET_PLATFORM}"
)

## COMPILATION FLAGS
add_definitions(-DPKCS11)
if(${TARGET_PLATFORM} MATCHES "86")
    set_target_properties(${TARGET_NAME}
        PROPERTIES
        COMPILE_FLAGS "-m32"
        LINK_FLAGS "-m32"
    )
endif()

#TODO: Change compile options to target_compile_options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wimplicit-function-declaration -Wstrict-prototypes -Wmissing-prototypes -pedantic -Wfatal-errors -Wall -fstack-protector-all -Wl,-z,noexecstack")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g3 -ggdb -O0 -rdynamic")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} ")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fPIC -Wl,--no-undefined")

################################
#### LIBRARIES
################################
set(LIBRARIES_PATH "${PROJECT_SOURCE_DIR}/../../libs")
message("${BOLDCYAN}Libraries path: " "${LIBRARIES_PATH}")

if(UNIX)
    set(LIBRARY_EXTENSION "a")
elseif(WIN32)
    set(LIBRARY_EXTENSION "lib")
endif()

# LIBCURL #
set(LIBCURL_NAME "libcurl")
if(UNIX)
    set(LIBCURL_PATH "${LIBRARIES_PATH}/linux/libcurl")
elseif(WIN32)
    set(LIBCURL_PATH "${LIBRARIES_PATH}/windows/libcurl")
    set(LIBCURL_NAME "${LIBCURL_NAME}_a")
    if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
        set(LIBCURL_NAME "${LIBCURL_NAME}_debug")
    endif()
endif()
set(LIBCURL_PATH "${LIBCURL_PATH}/${BUILD_TYPE}/x${TARGET_PLATFORM}")

target_include_directories(${TARGET_NAME} PRIVATE ${LIBCURL_PATH}/include/curl)
target_link_libraries(${TARGET_NAME} PRIVATE ${LIBCURL_PATH}/lib/${LIBCURL_NAME}.${LIBRARY_EXTENSION})
message("${BOLDGREEN}libcurl used: ${LIBCURL_PATH} ${RESETCOLOR}")

# OPENSSL #
if(UNIX)
    set(OPENSSL_LIB_CRYPTO "libcrypto")
    set(OPENSSL_LIB_SSL "libssl")
    set(OPENSSL_PATH "${LIBRARIES_PATH}/linux/openssl")
    set(OPENSSL_PATH "${OPENSSL_PATH}/${BUILD_TYPE}/x${TARGET_PLATFORM}")
elseif(WIN32)
    set(OPENSSL_LIB_CRYPTO "libeay32")
    set(OPENSSL_LIB_SSL "ssleay32")
    set(OPENSSL_PATH "${LIBRARIES_PATH}/windows/openssl")
    set(OPENSSL_PATH "${OPENSSL_PATH}/release/x${TARGET_PLATFORM}")
endif()

target_include_directories(${TARGET_NAME} PUBLIC ${OPENSSL_PATH}/include)
message("${BOLDGREEN}OpenSSL used: ${OPENSSL_PATH}${RESETCOLOR}")

target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_PATH}/lib/${OPENSSL_LIB_SSL}.${LIBRARY_EXTENSION})
target_link_libraries(${TARGET_NAME} PRIVATE ${OPENSSL_PATH}/lib/${OPENSSL_LIB_CRYPTO}.${LIBRARY_EXTENSION})

# ZLIB #
set(ZLIB_PATH ${LIBRARIES_PATH}/linux/zlib/release/x${TARGET_PLATFORM}/)
target_include_directories(${TARGET_NAME} PRIVATE ${ZLIB_PATH}/include)
target_link_libraries(${TARGET_NAME} PRIVATE ${ZLIB_PATH}/lib/libz.${LIBRARY_EXTENSION})
message("${BOLDGREEN}zLib used: ${ZLIB_PATH}${RESETCOLOR}")

# DL #
target_link_libraries(${TARGET_NAME} PRIVATE ${CMAKE_DL_LIBS})

# MATH #
target_link_libraries(${TARGET_NAME} PRIVATE m)

################################
#### SOURCES
################################

# PKCS11_CONNECTOR
set(SOURCES_PATH_PKCS11_CONNECTOR_ROOT ${PROJECT_SOURCE_DIR}/src)
message("${BOLDCYAN}Source code root: " ${SOURCES_PATH_PKCS11_CONNECTOR_ROOT} "${RESETCOLOR}")
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_PKCS11_CONNECTOR_ROOT})
target_sources(${TARGET_NAME}
    PRIVATE
        "${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/cryptokiTypes.c"
        "${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/cryptoki.c"
        "${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/cryptoki_helper.c"

)

## AKV_MODULE
set(SOURCES_PATH_AKV_MODULE ${PROJECT_SOURCE_DIR}/../../Modules/AKV_Module)
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_AKV_MODULE})
target_sources(${TARGET_NAME}
    PRIVATE
        "${SOURCES_PATH_AKV_MODULE}/src/clientRestTypes.c"
        "${SOURCES_PATH_AKV_MODULE}/src/clientRest.c"
        "${SOURCES_PATH_AKV_MODULE}/src/clientRest_helper.c"
        "${SOURCES_PATH_AKV_MODULE}/src/parser_helper.c"
		"${SOURCES_PATH_AKV_MODULE}/src/SecureConfiguration.c"
)

## COMMON_MODULE
set(SOURCES_PATH_COMMON_MODULE ${PROJECT_SOURCE_DIR}/../../Modules/Common_Module)
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_COMMON_MODULE})
target_sources(${TARGET_NAME}
    PRIVATE
	    "${SOURCES_PATH_COMMON_MODULE}/src/cJSON.c"
        "${SOURCES_PATH_COMMON_MODULE}/src/librb64u.c"
)

# CRYPTOKI
set(SOURCES_PATH_PKCS11_CONNECTOR_CRYPTOKI ${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/cryptoki)
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_PKCS11_CONNECTOR_CRYPTOKI})

# HELPERS
set(SOURCES_PATH_PKCS11_CONNECTOR_HELPERS ${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/Helpers)
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_PKCS11_CONNECTOR_HELPERS})
target_sources(${TARGET_NAME}
    PRIVATE
        "${SOURCES_PATH_PKCS11_CONNECTOR_HELPERS}/common.c"
)

# DEBUG
#set(SOURCES_PATH_PKCS11_CONNECTOR_DEBUG ${SOURCES_PATH_PKCS11_CONNECTOR_ROOT}/Debug)
set(SOURCES_PATH_PKCS11_CONNECTOR_DEBUG  ${PROJECT_SOURCE_DIR}/../../Modules/Common_Module/src)
target_include_directories(${TARGET_NAME} PRIVATE ${SOURCES_PATH_PKCS11_CONNECTOR_DEBUG})
target_sources(${TARGET_NAME}
    PRIVATE
        "${SOURCES_PATH_PKCS11_CONNECTOR_DEBUG}/Debug.c"
)
