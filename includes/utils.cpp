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