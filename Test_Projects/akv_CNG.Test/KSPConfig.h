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

#ifndef __SAMPLE_KSP_CONFIG_H__
#define __SAMPLE_KSP_CONFIG_H__

#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

//error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INTERNAL_ERROR           ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_SIGNATURE        ((NTSTATUS)0xC000A000L)
#define STATUS_NOT_FOUND				((NTSTATUS)0xC0000225L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

///////////////////////////////////////////////////////////////////////////////
//
// The following section defines the characteristics of the
// provider being registered...
//
///////////////////////////////////////////////////////////////////////////////
//
// File name of sample key storage provider's binary. *NO* path.
//
#define KSP_BINARY				  L"CNG_Connector.dll"
#define GRADIANT_KSP_PROVIDER_NAME           L"Gradiant Key Storage Provider" //name of the sample KSP provider

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations...
//
///////////////////////////////////////////////////////////////////////////////

NTSTATUS EnumerateProviders(unsigned long *numProv, PWSTR provider);
#endif