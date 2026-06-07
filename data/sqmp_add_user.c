#include <errno.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_USERS_FILE "users.txt"

int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: sqmp-add-user <username> <password> [users-file]\n");
        return 1;
    }

    const char *username   = argv[1];
    const char *password   = argv[2];
    const char *users_file = argc == 4 ? argv[3] : DEFAULT_USERS_FILE;
    size_t      ulen       = strlen(username);

    if (ulen == 0) {
        fprintf(stderr, "Username must not be empty\n");
        return 1;
    }

    FILE *f = fopen(users_file, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *colon = strchr(line, ':');
            if (!colon) continue;
            if ((size_t)(colon - line) == ulen &&
                strncmp(line, username, ulen) == 0) {
                fclose(f);
                fprintf(stderr, "User '%s' already exists\n", username);
                return 1;
            }
        }
        fclose(f);
    }

    uint8_t hash[32];
    SHA256((const unsigned char *)password, strlen(password), hash);

    f = fopen(users_file, "a");
    if (!f) {
        fprintf(stderr, "Cannot open %s: %s\n", users_file, strerror(errno));
        return 1;
    }
    fprintf(f, "%s:", username);
    for (int i = 0; i < 32; i++)
        fprintf(f, "%02x", hash[i]);
    fprintf(f, "\n");
    fclose(f);

    printf("Added user '%s'\n", username);
    return 0;
}
