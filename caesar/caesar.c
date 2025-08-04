#include <cs50.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cipher(int k, string s);

int main(int argc, string argv[])
{
    if (argc != 2)
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }

    for (int i = 0; i < strlen(argv[1]); i++)
    {
        if (!(isdigit(argv[1][i])))
        {
            printf("Usage: ./caesar key\n");
            return 1;
        }
    }

    int k = atoi(argv[1]);

    if (k < 0)
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }

    string s = get_string("plaintext: ");
    cipher(k, s);

    return 0;
}

void cipher(int k, string s)
{
    for (int i = 0, n = strlen(s); i < n; i++)
    {
        if (isalpha(s[i]))
        {
            char character = islower(s[i]) ? 'a' : 'A';
            s[i] = (s[i] - character + k) % 26 + character;
        }
    }

    printf("ciphertext: %s\n", s);
}
