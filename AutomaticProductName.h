#pragma once

#ifdef _WIN64
#ifdef UNICODE
#define ORIGINAL_FILENAME   L"etherwake (x64 Unicode) (MSVC)\0"
#define PRODUCT_NAME        L"etherwake - Version 1.0.04.008\r\n(Build 78) - (x64 Unicode) (MSVC)\0"
#else
#define ORIGINAL_FILENAME   "etherwake (x64 MBCS) (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.008\r\n(Build 78) - (x64 MBCS) (MSVC)\0"
#endif
#elif _WIN32
#ifdef UNICODE
#define ORIGINAL_FILENAME   L"etherwake (x86 Unicode) (MSVC)\0"
#define PRODUCT_NAME        L"etherwake - Version 1.0.04.008\r\n(Build 78) - (x86 Unicode) (MSVC)\0"
#else
#define ORIGINAL_FILENAME   "etherwake (x86 MBCS) (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.008\r\n(Build 78) - (x86 MBCS) (MSVC)\0"
#endif
#else
#define ORIGINAL_FILENAME   "etherwake (MSVC)\0"
#define PRODUCT_NAME        "etherwake - Version 1.0.04.008\r\n(Build 78) - (MSVC)\0"
#endif
