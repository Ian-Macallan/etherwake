#pragma once

#ifndef AUTOMATICPRODUCTNAME_H
#define AUTOMATICPRODUCTNAME_H    1

#ifdef _WIN64
#ifdef UNICODE
#define ORIGINAL_FILENAME   L"etherwake (x64 Unicode) (MSVC)\0"
#define PRODUCT_NAME        L"etherwake - Version 1.0.04.015\r\n(Build 85) - (x64 Unicode) (MSVC)\0"
#else
#define ORIGINAL_FILENAME   "etherwake (x64 MBCS) (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.015\r\n(Build 85) - (x64 MBCS) (MSVC)\0"
#endif
#elif _WIN32
#ifdef UNICODE
#define ORIGINAL_FILENAME   L"etherwake (x86 Unicode) (MSVC)\0"
#define PRODUCT_NAME        L"etherwake - Version 1.0.04.015\r\n(Build 85) - (x86 Unicode) (MSVC)\0"
#else
#define ORIGINAL_FILENAME   "etherwake (x86 MBCS) (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.015\r\n(Build 85) - (x86 MBCS) (MSVC)\0"
#endif
#else
#define ORIGINAL_FILENAME   "etherwake (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.015\r\n(Build 85) - (MSVC)\0"
#endif

#endif
