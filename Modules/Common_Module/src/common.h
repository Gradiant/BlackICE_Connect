/*******************************************************************************
 *
 *                                   GRADIANT
 *
 *     Galician Research And Development center In AdvaNced Telecommunication
 *
 *
 * Copyright (c) 2019 by Gradiant. All rights reserved.
 * Licensed under the Mozilla Public License v2.0 (the "LICENSE").
 * https://github.com/Gradiant/BlackICE_Connect/LICENSE
 *******************************************************************************/

#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

// Avoids changing all of the references to minwindef.h's BOOL
#ifndef _WIN32
    typedef int BOOL;
    typedef int errno_t;

    #ifndef FALSE
        #define FALSE 0
    #endif
    #ifndef TRUE
        #define TRUE 1
    #endif

    /**
    * @brief Wraps a call to strdup (POSIX) when str != NULL. Returns NULL otherwise.
        GCC's strdup will crash (calling strlen) when str == NULL.
    * @param str. String to be duplicated.
    * @returns. Pointer to the duplicated string.
    */
    extern char* _strdup(const char* str);
#endif

#endif //!COMMON_H_INCLUDED