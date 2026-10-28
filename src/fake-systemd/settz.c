#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZONEINFO_DIR "/usr/share/zoneinfo/"
#define LOCALTIME_PATH "/etc/localtime"
#define LOCALTIME_STAGING_PATH "/etc/.localtime.settz"
#define MAX_ZONE_LENGTH 256

static int is_allowed_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c == '_' || c == '+' || c == '-' || c == '/';
}

static int is_valid_zone_name(const char *zone) {
    size_t length = strlen(zone);
    if (length == 0 || length >= MAX_ZONE_LENGTH) {
        return 0;
    }
    if (zone[0] == '/' || strstr(zone, "..") != NULL) {
        return 0;
    }
    for (size_t i = 0; i < length; i++) {
        if (!is_allowed_char(zone[i])) {
            return 0;
        }
    }
    return 1;
}

static int is_regular_zone_file(const char *target) {
    struct stat info;
    if (stat(target, &info) != 0) {
        return 0;
    }
    return S_ISREG(info.st_mode);
}

static int fail_step(const char *step) {
    fprintf(stderr, "settz: %s failed: %s\n", step, strerror(errno));
    return 1;
}

int main(int argc, char *argv[]) {
    if (access("/.container", F_OK) != 0) {
        fprintf(stderr, "settz: refusing to run outside a container (/.container not found)\n");
        return 1;
    }

    if (argc != 2) {
        fprintf(stderr, "usage: settz <zone>\n");
        return 2;
    }

    const char *zone = argv[1];
    char target[sizeof(ZONEINFO_DIR) + MAX_ZONE_LENGTH];

    if (!is_valid_zone_name(zone)) {
        fprintf(stderr, "settz: invalid time zone '%s'\n", zone);
        return 1;
    }

    snprintf(target, sizeof(target), ZONEINFO_DIR "%s", zone);

    if (!is_regular_zone_file(target)) {
        fprintf(stderr, "settz: invalid time zone '%s'\n", zone);
        return 1;
    }

    if (unlink(LOCALTIME_STAGING_PATH) != 0 && errno != ENOENT) {
        return fail_step("unlink");
    }
    if (symlink(target, LOCALTIME_STAGING_PATH) != 0) {
        return fail_step("symlink");
    }
    if (rename(LOCALTIME_STAGING_PATH, LOCALTIME_PATH) != 0) {
        return fail_step("rename");
    }

    return 0;
}
