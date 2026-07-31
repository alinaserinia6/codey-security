/**
 * Intentionally vulnerable C code for demonstration.
 * Contains buffer overflow and integer overflow vulnerabilities.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// VULNERABILITY 1: Buffer Overflow (CVE-2021-3156 pattern)
void copy_input(char *input) {
    char buffer[64];
    // DANGEROUS: strcpy without bounds checking
    strcpy(buffer, input);  // CWE-787 - Buffer Overflow
    printf("Buffer: %s\n", buffer);
}

// VULNERABILITY 2: Command Injection
void execute_command(char *cmd) {
    // DANGEROUS: system with user input
    system(cmd);  // CWE-78 - Command Injection
}

// VULNERABILITY 3: Integer Overflow (CVE-2017-7529 pattern)
int process_range(int start, int length) {
    // DANGEROUS: Integer overflow
    int end = start + length;  // CWE-190 - Integer Overflow
    if (end < start) {
        // Overflow detected but handled poorly
        return -1;
    }
    return end;
}

// VULNERABILITY 4: Unsafe string operations
void unsafe_string_ops(char *src) {
    char dest[32];
    // DANGEROUS: strcat without bounds checking
    strcat(dest, src);  // CWE-119 - Buffer Overflow
}

// SAFE version (for comparison)
void safe_copy_input(char *input) {
    char buffer[64];
    // SAFE: Use strncpy with bounds checking
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Buffer: %s\n", buffer);
}

// SAFE command execution
void safe_execute_command(char *cmd) {
    // SAFE: Use execve with proper argument handling
    char *args[] = {"/bin/sh", "-c", cmd, NULL};
    execve("/bin/sh", args, NULL);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        copy_input(argv[1]);
        execute_command(argv[1]);
        unsafe_string_ops(argv[1]);
    }
    
    int result = process_range(10, 20);
    printf("Range result: %d\n", result);
    
    return 0;
}
