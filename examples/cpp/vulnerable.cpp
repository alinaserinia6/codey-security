#include <cstring>

void vulnerable_copy(const char *input) {
    char buffer[16];
    std::strcpy(buffer, input);
}

int main(int argc, char **argv) {
    if (argc > 1) vulnerable_copy(argv[1]);
    return 0;
}
