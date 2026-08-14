#pragma once
#include <windows.h>

DWORD ror13(const char* s);
DWORD djb2(const char* s);
DWORD fnv1a(const char* s);
DWORD crc32(const char* s);
DWORD sdbm(const char* s);

DWORD crc32_base(const char* s);
DWORD mix_hash(DWORD h);
DWORD mixed_crc32(const char* s);
DWORD mixed_crc32(const char* s);
DWORD mixed_ror13(const char* s);
DWORD mixed_fnv1a(const char* s);