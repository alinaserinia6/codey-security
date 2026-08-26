#include <string.h>
void CWE120_good(void) {
    char dst[16];
    char *src = "0123456789";
    strncpy(dst, src, sizeof(dst) - 1);
    dst[sizeof(dst) - 1] = '\\0';
}
int main(void) { CWE120_good(); return 0; }
