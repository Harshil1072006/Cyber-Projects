#include <stdio.h>
#include <string.h>

void process_data(char *input) {
    char buffer[50];
    
    // VULNERABILITY: Classic Buffer Overflow (strcpy into a fixed-size buffer)
    strcpy(buffer, input);
    
    printf("Processed: %s\n", buffer);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_data(argv[1]);
    } else {
        printf("Please provide an argument.\n");
    }
    return 0;
}
