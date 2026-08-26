#include <string.h>

void copy_input(const char *input) {
    char buffer[16];
    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, input);
}

int main(void) { copy_input("hello"); return 0; }
