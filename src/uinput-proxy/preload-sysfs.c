#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <linux/magic.h>

#include "preload.h"

#define STRINGIFY_(x) #x
#define STRINGIFY(x)  STRINGIFY_(x)

/* ------------------------------------------------------------------ */
/* Redirect table                                                     */
/* ------------------------------------------------------------------ */

typedef enum { MATCH_TREE, MATCH_PREFIX, MATCH_EXACT } match_kind_t;

struct redirect {
    const char  *system_path;
    const char  *mirror_path;
    match_kind_t kind;
};

static const struct redirect redirects[] = {
    { "/sys/class/input",                             "class/input",                              MATCH_TREE   },
    { "/sys/devices/virtual/input",                   "devices/virtual/input",                    MATCH_TREE   },
    { "/sys/dev/char/" STRINGIFY(INPUT_MAJOR) ":",    "dev/char/" STRINGIFY(INPUT_MAJOR) ":",     MATCH_PREFIX },
    { "/proc/bus/input/devices",                      PROC_INPUT_DEVICES_MIRROR,                  MATCH_EXACT  },
};

#define REDIRECT_COUNT (sizeof(redirects) / sizeof(redirects[0]))

static const char *const entry_components[] = {
    "sys", "class", "input", "devices", "virtual", "dev", "char", "proc", "bus",
};

static const char *match_rest(const char *path, const char *prefix, match_kind_t kind) {
    size_t len = strlen(prefix);
    if (strncmp(path, prefix, len) != 0) return NULL;
    const char *rest = path + len;
    switch (kind) {
    case MATCH_TREE:   return (*rest == '\0' || *rest == '/') ? rest : NULL;
    case MATCH_PREFIX: return rest;
    case MATCH_EXACT:  return *rest == '\0' ? rest : NULL;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* System path -> mirror path                                         */
/* ------------------------------------------------------------------ */

bool sysfs_redirect(const char *path, char *mirror) {
    if (!path || path[0] != '/' || (path[1] != 's' && path[1] != 'p')) return false;
    for (size_t i = 0; i < REDIRECT_COUNT; i++) {
        const char *rest = match_rest(path, redirects[i].system_path, redirects[i].kind);
        if (!rest) continue;
        int n = snprintf(mirror, PATH_MAX, "%s/%s%s", SYSFS_MIRROR_ROOT, redirects[i].mirror_path, rest);
        return n > 0 && n < PATH_MAX;
    }
    return false;
}

static bool may_enter_redirect(const char *relative) {
    size_t len = strcspn(relative, "/");
    if (strncmp(relative, STRINGIFY(INPUT_MAJOR) ":", strlen(STRINGIFY(INPUT_MAJOR) ":")) == 0)
        return true;
    for (size_t i = 0; i < sizeof(entry_components) / sizeof(entry_components[0]); i++)
        if (strlen(entry_components[i]) == len && strncmp(relative, entry_components[i], len) == 0)
            return true;
    return false;
}

/* libudev's chase() walks sysfs one component at a time with openat(dirfd, name),
 * so a relative name only reveals where it leads once joined to the directory the
 * dirfd refers to, which /proc/self/fd/N names. */
bool sysfs_redirect_at(int dirfd, const char *path, char *mirror) {
    if (!path) return false;
    if (path[0] == '/') return sysfs_redirect(path, mirror);
    if (path[0] == '\0' || !may_enter_redirect(path)) return false;

    char link[64];
    if (dirfd == AT_FDCWD) snprintf(link, sizeof(link), "/proc/self/cwd");
    else                   snprintf(link, sizeof(link), "/proc/self/fd/%d", dirfd);

    char base[PATH_MAX];
    ssize_t n = real_readlink ? real_readlink(link, base, sizeof(base) - 1) : -1;
    if (n <= 0) return false;
    base[n] = '\0';
    if (strncmp(base, "/sys", 4) != 0 && strncmp(base, "/proc", 5) != 0 && strcmp(base, "/") != 0)
        return false;

    char full[PATH_MAX];
    int len = snprintf(full, sizeof(full), "%s/%s", strcmp(base, "/") == 0 ? "" : base, path);
    if (len <= 0 || len >= (int)sizeof(full)) return false;
    return sysfs_redirect(full, mirror);
}

/* ------------------------------------------------------------------ */
/* Mirror path -> system path                                         */
/* ------------------------------------------------------------------ */

ssize_t sysfs_unredirect(char *path, ssize_t len, size_t bufsz) {
    static const char root[] = SYSFS_MIRROR_ROOT "/";
    size_t root_len = sizeof(root) - 1;
    if (len < (ssize_t)root_len || strncmp(path, root, root_len) != 0) return len;

    char relative[PATH_MAX];
    size_t rel_len = (size_t)len - root_len;
    if (rel_len >= sizeof(relative)) return len;
    memcpy(relative, path + root_len, rel_len);
    relative[rel_len] = '\0';

    for (size_t i = 0; i < REDIRECT_COUNT; i++) {
        const char *rest = match_rest(relative, redirects[i].mirror_path, redirects[i].kind);
        if (!rest) continue;
        char system[PATH_MAX];
        int n = snprintf(system, sizeof(system), "%s%s", redirects[i].system_path, rest);
        if (n <= 0 || (size_t)n > bufsz) return len;
        memcpy(path, system, (size_t)n);
        if ((size_t)n < bufsz) path[n] = '\0';
        return n;
    }
    return len;
}

long sysfs_mirror_fs_type(int fd) {
    static const char root[] = SYSFS_MIRROR_ROOT "/";
    char link[64], path[PATH_MAX];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = real_readlink ? real_readlink(link, path, sizeof(path) - 1) : -1;
    if (n < (ssize_t)(sizeof(root) - 1) || strncmp(path, root, sizeof(root) - 1) != 0) return 0;
    n = sysfs_unredirect(path, n, sizeof(path) - 1);
    path[n] = '\0';
    if (strncmp(path, "/sys/", 5) == 0)  return SYSFS_MAGIC;
    if (strncmp(path, "/proc/", 6) == 0) return PROC_SUPER_MAGIC;
    return 0;
}
