#include <stdio.h>
#include <windows.h>

DWORD Ror13Hash(char* str) {
    DWORD hash = 0;
    while (*str) {
        // Rotate right by 13 bits
        hash = (hash >> 13) | (hash << (32 - 13));
        // Add the next character byte
        hash += *str;
        str++;
    }
    return hash;
}

int main(int argc, char* argv[]) {
    // Safety check: ensure an argument was passed
    if (argc < 2) {
        printf("Usage: %s <string_to_hash>\n", argv[0]);
        return 1;
    }

    // Pass the command-line argument directly to the function
    printf("Hash: 0x%08X\n", Ror13Hash(argv[1]));
    return 0;
}