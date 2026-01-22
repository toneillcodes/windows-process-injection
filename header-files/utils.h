#ifndef UTILS_H
#define UTILS_H

#include <windows.h> // Needed for wchar_t and NULL

// Function Declarations
int my_atoi(const char* s);
int my_strlen(const char* inputString);
int my_strlen_for(const char* s);
int my_strcmp(const char* s1, const char* s2);
int my_stricmp(const char* s1, const char* s2);
int my_wcsicmp(const wchar_t* s1, const wchar_t* s2);

#endif 