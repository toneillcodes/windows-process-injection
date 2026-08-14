#pragma once
#include "hash_functions.h"

DWORD ror13(const char* s)
{
    DWORD h = 0;
    while (*s)
    {
        h = _rotr(h, 13);
        h += (DWORD)(*s | 0x20);
        s++;
    }
    return h;
}

DWORD djb2(const char* s)
{
    DWORD h = 5381;            // embedded immediate
    while (*s)
    {
        BYTE c = (*s | 0x20);  // lowercase normalization
        h = ((h << 5) + h) + c; // h * 33 + c
        s++;
    }
    return h;
}

DWORD fnv1a(const char* s)
{
    DWORD h = 0x811C9DC5;      // FNV offset basis (embedded immediate)
    while (*s)
    {
        BYTE c = (*s | 0x20);  // lowercase normalization
        h ^= c;
        h *= 0x01000193;       // FNV prime (embedded immediate)
        s++;
    }
    return h;
}

DWORD crc32(const char* s)
{
    DWORD crc = 0xFFFFFFFF;    // embedded immediate
    while (*s)
    {
        BYTE c = (*s | 0x20);  // lowercase normalization
        crc ^= c;

        for (int i = 0; i < 8; i++)
        {
            DWORD mask = (crc & 1) ? 0xFFFFFFFF : 0x00000000;
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }

        s++;
    }
    return ~crc;
}

DWORD sdbm(const char* s)
{
    DWORD h = 0;
    while (*s)
    {
        BYTE c = (*s | 0x20);  // lowercase normalization
        h = c + (h << 6) + (h << 16) - h;
        s++;
    }
    return h;
}

DWORD crc32_base(const char* s)
{
    DWORD crc = 0xFFFFFFFF;
    while (*s)
    {
        BYTE c = (*s | 0x20);
        crc ^= c;

        for (int i = 0; i < 8; i++)
        {
            DWORD mask = (crc & 1) ? 0xFFFFFFFF : 0x00000000;
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }

        s++;
    }
    return ~crc;
}

DWORD mix_hash(DWORD h)
{
    // All constants are embedded immediates → PIC-safe
    h ^= 0xA3B1C2D3;          // custom “key-like” constant
    h = _rotl(h, 7);          // rotate left
    h *= 0x85EBCA6B;          // custom multiplier (inspired by Murmur-ish constants)
    h ^= (h >> 16);
    return h;
}

DWORD mixed_crc32(const char* s)
{
    DWORD h = crc32_base(s);
    return mix_hash(h);
}

DWORD mixed_ror13(const char* s)
{
    DWORD h = ror13(s);
    return mix_hash(h);
}

DWORD mixed_fnv1a(const char* s)
{
    DWORD h = fnv1a(s);
    return mix_hash(h);
}