#pragma once
#include <stdio.h>

#include "hashit.h"
#include "utils.h"

hash_fn_t lookup_hash(hash_entry_t* reg, int count, const char* name)
{
    for (int i = 0; i < count; i++)
    {
        if (my_stricmp(reg[i].name, name) == 0)
            return reg[i].fn;
    }
    return NULL;
}

DWORD hash_api(hash_fn_t fn, const char* s)
{
    return fn(s);
}

void list_hashes(hash_entry_t* reg, int count)
{
    for (int i = 0; i < count; i++) {
        printf("%s", reg[i].name); 
        if(i == (count-1))
            printf("\n");
        else 
            printf(", ");
    }
}