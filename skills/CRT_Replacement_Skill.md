# CRT Replacement Generator Skill
# Purpose:
#   Generate PIC-safe, dependency-free C implementations of CRT functions
#   following the user's existing utils.c / utils.h conventions.
#
# Input:
#   - function_name: The CRT function to replace (e.g., strcpy, memcmp)
#   - signature: Optional explicit signature if user wants full control
#   - variant: Optional (safe, len, wide, etc.)
#
# Output:
#   - utils.c code block
#   - utils.h declaration block
#
# Rules:
#   - All generated functions MUST:
#       * Be named my_<function_name>
#       * Use only pointer arithmetic and simple loops
#       * Avoid CRT calls entirely
#       * Avoid compiler intrinsics
#       * Avoid global variables
#       * Be PIC-safe (no absolute addressing, no static data)
#       * Match the formatting style of the provided utils.c
#   - If the CRT function has multiple common variants (e.g., strcpy_safe),
#     generate them all unless the user specifies otherwise.
#   - If the function is ambiguous (e.g., "compare"), ask the user which CRT
#     function they want (strcmp, memcmp, wcsicmp, etc.)
#
# Style conventions:
#   - Opening brace on same line
#   - Minimal whitespace
#   - Use while loops unless for-loops improve clarity
#   - Return original pointer for string functions
#   - Use casts identical to existing code (BYTE*, SIZE_T, etc.)
#
# Output format:
#   The skill MUST output two sections:
#
#   === utils.c ===
#   <code>
#   ...implementation...
#   </code>
#
#   === utils.h ===
#   <code>
#   ...prototype...
#   </code>
#
# Examples:
#
# User: "Generate memcmp"
#
# Output:
#
# === utils.c ===
# <code>
# int my_memcmp(const void* a, const void* b, SIZE_T len) {
#     const BYTE* p1 = (const BYTE*)a;
#     const BYTE* p2 = (const BYTE*)b;
#     while (len--) {
#         BYTE c1 = *p1++;
#         BYTE c2 = *p2++;
#         if (c1 != c2)
#             return (int)c1 - (int)c2;
#     }
#     return 0;
# }
# </code>
#
# === utils.h ===
# <code>
# int my_memcmp(const void* a, const void* b, SIZE_T len);
# </code>
#
# End of Skill
