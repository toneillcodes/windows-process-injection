#ifndef UTILS_H
#define UTILS_H

#include <windows.h> // Needed for wchar_t and NULL
#include <tlhelp32.h>

// Function Declarations
int my_atoi(const char* s);
int my_strlen(const char* inputString);
int my_strlen_for(const char* s);
int my_strcmp(const char* s1, const char* s2);
int my_stricmp(const char* s1, const char* s2);
int my_wcsicmp(const wchar_t* s1, const wchar_t* s2);
void* my_memcpy(void* dst, const void* src, SIZE_T len);

char* my_strcpy(char* dst, const char* src);
char* my_strcpy_safe(char* dst, const char* src);
char* my_strcpy_len(char* dst, const char* src, SIZE_T maxLen);
char* my_strncpy(char* dst, const char* src, size_t n);
char* my_strchr(const char* s, int ch);
char* my_strchr_safe(const char* s, int ch);
char* my_strcat(char* dst, const char* src);
char* my_strcat_safe(char* dst, const char* src);

#endif 