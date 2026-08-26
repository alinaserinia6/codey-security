#include <string.h>
void CWE120_bad(void) {
    char dst[8];
    char *src = "0123456789";
    strcpy(dst, src);
}
int main(void) { CWE120_bad(); return 0; }
