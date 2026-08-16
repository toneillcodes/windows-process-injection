#include <stdio.h>
#include <stdint.h>
#include <windows.h>

// Prototype from utils.h
void* my_memset(void* dst, int value, SIZE_T len);

// Simple hex dump helper (for visual validation)
static void dump(const uint8_t* buf, SIZE_T len)
{
    for (SIZE_T i = 0; i < len; i++)
        printf("%02X ", buf[i]);
    printf("\n");
}

int main(void)
{
    uint8_t buffer[16];

    printf("=== Test 1: Fill with 0x41 ('A') ===\n");
    my_memset(buffer, 0x41, sizeof(buffer));
    dump(buffer, sizeof(buffer));

    printf("=== Test 2: Fill with 0x00 ===\n");
    my_memset(buffer, 0x00, sizeof(buffer));
    dump(buffer, sizeof(buffer));

    printf("=== Test 3: Fill first half with 0xFF ===\n");
    my_memset(buffer, 0xFF, sizeof(buffer) / 2);
    dump(buffer, sizeof(buffer));

    printf("=== Test 4: Zero-length fill (should not modify buffer) ===\n");
    my_memset(buffer, 0xAA, 0);   // no-op
    dump(buffer, sizeof(buffer));

    printf("=== Test 5: Validate return pointer ===\n");
    void* ret = my_memset(buffer, 0x12, sizeof(buffer));
    printf("Return pointer matches buffer: %s\n", (ret == buffer) ? "YES" : "NO");
    dump(buffer, sizeof(buffer));

    printf("=== Test 6: Fill with incremental pattern ===\n");
    for (int i = 0; i < 16; i++)
        buffer[i] = (uint8_t)i;

    my_memset(buffer + 4, 0x7E, 6); // overwrite middle region
    dump(buffer, sizeof(buffer));

    return 0;
}
