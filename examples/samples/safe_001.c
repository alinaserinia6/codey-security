#include <string.h>

void copy_safe(const char *input) {
    char buffer[16];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

int main(void) { copy_safe("hello"); return 0; }
