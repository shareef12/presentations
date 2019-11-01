#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// generated with `openssl rand -hex 4
#define SRAND_SEED  0xd0c96a49

static const char key_bin[] = "hello world";
static size_t key_bin_len = sizeof(key_bin) - 1;

void decrypt(char *plaintext, size_t len)
{
    for (int i = 0; i < len; i++) {
        for (int j = 0; j < i; j++) {
            (void)rand();
        }
        plaintext[i] ^= rand() & 0xff;
    }
}


int main(int argc, char *argv[])
{
    char input[64] = {0};

    srand(SRAND_SEED);

    printf("Enter the password: ");
    if (scanf("%63s", input) != 1) {
        return 1;
    }

    decrypt(input, strlen(input));

    if (memcmp(input, key_bin, key_bin_len) != 0) {
        puts("Nope.");
        return 1;
    }

    puts("Good password!");
    return 0;
}
