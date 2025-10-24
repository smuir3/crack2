#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;   // Maximum plaintext password length we will try
const int HASH_LEN = 33;   // MD5 hex string length including '\0' (32 + 1)

// Trim trailing newline and carriage return characters in-place.
static void trim_eol(char *s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r'))
        s[--n] = '\0';
}

char *tryWord(char *plaintext, char *hashFilename)
{
    // 1) Hash the plaintext.
    char *hex = md5(plaintext, (int)strlen(plaintext));
    if (!hex) return NULL;

    // 2) Open the hash file.
    FILE *hf = fopen(hashFilename, "r");
    if (!hf) {
        perror("open hash file");
        free(hex);
        return NULL;
    }

    // 3) Loop through the hash file, one line at a time.
    char line[HASH_LEN + 4]; // a little slack for newline
    while (fgets(line, sizeof line, hf)) {
        trim_eol(line);

        // 4) Compare the file’s hash with our computed hash.
        if (strcmp(line, hex) == 0) {
            fclose(hf);
            // Matched: return the computed hash.
            return hex;
        }
    }

    // 5) No match found: clean up and return NULL.
    fclose(hf);
    free(hex);
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    const char *hash_file = argv[1];
    const char *dict_file = argv[2];

    // Open the dictionary file for reading.
    FILE *df = fopen(dict_file, "r");
    if (!df) {
        perror("open dictionary");
        return 1;
    }

    int cracked = 0;

    // Read dictionary words one per line, try each against the hash file.
    char *word = NULL;
    size_t cap = 0;
    ssize_t nread;

    while ((nread = getline(&word, &cap, df)) != -1) {
        trim_eol(word);

        // Skip empty lines and words longer than PASS_LEN.
        size_t len = strlen(word);
        if (len == 0 || len > (size_t)PASS_LEN)
            continue;

        char *found = tryWord(word, (char *)hash_file);
        if (found) {
            // Print "hash word" as specified.
            printf("%s %s\n", found, word);
            ++cracked;
            free(found);
        }
    }

    free(word);
    fclose(df);

    // Display the number of hashes cracked.
    printf("%d hashes cracked!\n", cracked);
}
