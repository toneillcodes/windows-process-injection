#pragma once
#include <windows.h>
#include <stdio.h>

#include "utils.h"

typedef DWORD (*hash_fn_t)(const char*);

typedef struct {
    const char* name;
    hash_fn_t   fn;
} hash_entry_t;

typedef struct {
    hash_fn_t algorithm;
    DWORD     hash;
} HASHED_VALUE;

hash_fn_t lookup_hash(hash_entry_t* reg, int count, const char* name);

void list_hashes(hash_entry_t* reg, int count);

DWORD hash_api(hash_fn_t fn, const char* s);