#include "utils.h"

// custom string-to-integer conversion function
int my_atoi(const char* s) {
    int res = 0;
    while (*s >= '0' && *s <= '9') {
        res = res * 10 + (*s - '0');
        s++;
}
    return res;
}

// custom string length function
int my_strlen(const char* inputString) {
    if (inputString == NULL) return 0;

    int length = 0;
    while (inputString[length] != '\0') {
        length++;
    }
    return length;
}

// custom string length function with for loop optimization
int my_strlen_for(const char* s) {
    if (!s) return 0;

    const char* p = s;
    for (; *p; p++); // The semicolon at the end is the empty body

    return (int)(p - s);
}

// custom string comparison function
int my_strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    // Return the difference between the characters
    // (unsigned char) cast ensures correct behavior with extended ASCII
    return *(unsigned char*)s1 - *(unsigned char*)s2;
}

int my_stricmp(const char* s1, const char* s2) {
    while (*s1) {
        char c1 = *s1;
        char c2 = *s2;

        // Convert c1 to lowercase if it's uppercase
        if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
        // Convert c2 to lowercase if it's uppercase
        if (c2 >= 'A' && c2 <= 'Z') c2 += 32;

        if (c1 != c2) {
            return (unsigned char)c1 - (unsigned char)c2;
        }
        s1++;
        s2++;
    }
    return (unsigned char)*s1 - (unsigned char)*s2;
}

int my_wcsicmp(const wchar_t* s1, const wchar_t* s2) {
    wchar_t c1, c2;
    do {
        c1 = *s1++;
        c2 = *s2++;
        
        // Convert both to lowercase for comparison
        if (c1 >= L'A' && c1 <= L'Z') c1 += (L'a' - L'A');
        if (c2 >= L'A' && c2 <= L'Z') c2 += (L'a' - L'A');
        
        if (c1 == L'\0') return c1 - c2;
    } while (c1 == c2);
    
    return c1 - c2;
}

void* my_memcpy(void* dst, const void* src, SIZE_T len) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (len--) {
        *d++ = *s++;
    }
    return dst;
}

char* my_strcpy(char* dst, const char* src) {
    char* ret = dst;
    while ((*dst++ = *src++) != '\0');
    return ret;
}

char* my_strcpy_safe(char* dst, const char* src) {
    if (!dst || !src) return NULL;

    char* ret = dst;
    while ((*dst++ = *src++) != '\0');
    return ret;
}

char* my_strcpy_len(char* dst, const char* src, SIZE_T maxLen) {
    if (!dst || !src || maxLen == 0) return NULL;

    SIZE_T i = 0;
    while (i + 1 < maxLen && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}

char* my_strncpy(char* dst, const char* src, size_t n) {
    char* ret = dst;

    while (n-- && (*dst++ = *src++) != '\0')
        ;

    // If we broke out because src ended, pad the rest with '\0'
    while (n-- > 0)
        *dst++ = '\0';

    return ret;
}

char* my_strchr(const char* s, int ch) {
    while (*s) {
        if (*s == (char)ch)
            return (char*)s;
        s++;
    }
    return (ch == '\0') ? (char*)s : NULL;
}

char* my_strchr_safe(const char* s, int ch) {
    if (!s) return NULL;
    while (*s) {
        if (*s == (char)ch)
            return (char*)s;
        s++;
    }
    return (ch == '\0') ? (char*)s : NULL;
}

char* my_strcat(char* dst, const char* src) {
    char* ret = dst;

    while (*dst) dst++;        // find end of dst
    while ((*dst++ = *src++) != '\0');  // append src including null

    return ret;
}

char* my_strcat_safe(char* dst, const char* src) {
    if (!dst || !src) return NULL;

    char* ret = dst;
    while (*dst) dst++;
    while ((*dst++ = *src++) != '\0');

    return ret;
}