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

#include "common.h"
#include <string.h>

#ifndef _WIN32
    char* _strdup(const char* str) {
        if (str != NULL) {
            return strdup(str);
        } else {
            return NULL;
        }
    }
#endif