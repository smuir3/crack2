#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

const int PASS_LEN = 20;
const int HASH_LEN = 33;

static void trim_eol(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r'))
    {
        s[--n] = '\0';
    }
}

char * tryWord(char * plaintext, char * hashFilename)
{
    char *hex = md5(plaintext, (int)strlen(plaintext));
    if (!hex) return NULL;

    FILE *hf = fopen(hashFilename, "r");
    if (!hf)
    {
        perror("open hash file");
        free(hex);
        return NULL;
    }

    char line[HASH_LEN + 4];
    while (fgets(line, sizeof line, hf))
    {
        trim_eol(line);
        if (strcmp(line, hex) == 0)
        {
            fclose(hf);
            return hex;   // caller frees
        }
    }

    fclose(hf);
    free(hex);
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // keep the starter test
    char *found = tryWord("hello", "hashes00.txt");
    printf("%s %s\n", found, "hello");
    free(found);
}