#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    char buffer1[1024];
    char buffer2[1024];
    memset(buffer1, 0, sizeof(buffer1));
    memset(buffer2, 0, sizeof(buffer2));

    printf("Enter a string: ");
    fflush(stdout);

    ssize_t len = read(STDIN_FILENO, buffer1, sizeof(buffer1) - 1);
    putchar('\n');
    if (len <= 0) {
        exit(1);
    }

    memcpy(buffer2, &buffer1[4], *(unsigned int *)buffer1);
    printf("You sent: %s\n", buffer2);
    return 0;
}
