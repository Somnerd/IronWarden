#include <stdlib.h>

long long __isoc23_strtoll(const char *restrict nptr, char **restrict endptr, int base) {
    return strtoll(nptr, endptr, base);
}

unsigned long long __isoc23_strtoull(const char *restrict nptr, char **restrict endptr, int base) {
    return strtoull(nptr, endptr, base);
}

long __isoc23_strtol(const char *restrict nptr, char **restrict endptr, int base) {
    return strtol(nptr, endptr, base);
}
