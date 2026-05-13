#include <stdio.h>
#include <string.h>

void process_data_safe(const char *input) {
    char buffer[50];
    
    // SAFE: Using strncpy to prevent buffer overflow, ensuring null-termination
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    printf("Processed safely: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data_safe(argv[1]);
    } else {
        printf("Please provide an argument.\n");
    }
    return 0;
}
