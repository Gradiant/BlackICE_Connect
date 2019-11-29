target_sources(${TARGET_NAME}
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11f.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11t.h"
        "${CMAKE_CURRENT_SOURCE_DIR}/cryptoki.h"
)
message("${BOLDWHITE}Included ${CMAKE_CURRENT_SOURCE_DIR}${RESETCOLOR}")
