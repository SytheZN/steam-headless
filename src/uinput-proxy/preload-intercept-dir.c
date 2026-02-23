#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "preload.h"

/* ------------------------------------------------------------------ */
/* opendir                                                            */
/* ------------------------------------------------------------------ */

bool should_intercept_opendir(const char *path) {
    path_info_t pi = classify_path(path);
    switch (pi.cls) {
    case PATH_DEV_INPUT_DIR:
    case PATH_SYSFS_CLASS_DIR:
    case PATH_SYSFS_VIRT_DIR:
        return true;
    case PATH_SYSFS_INPUT:
        return is_sysfs_dir_attr(pi.remainder);
    case PATH_SYSFS_EVENT:
        return pi.remainder[0] == '\0';
    default:
        return false;
    }
}

DIR *intercept_opendir(const char *path) {
    dbg("opendir: path=%s", path);
    path_info_t pi = classify_path(path);

    if (pi.cls == PATH_DEV_INPUT_DIR) {
        /* Real device nodes exist (mknod), pass through */
        sysfs_cache_invalidate();
        return real_opendir(path);
    }

    if (pi.cls == PATH_SYSFS_CLASS_DIR) {
        int ids[MAX_DEVICES];
        int count = query_device_list(ids);
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        for (int i = 0; i < count; i++) {
            char name[32];
            snprintf(name, sizeof(name), "event%d", ids[i]);
            fake_dir_add(d, name, DT_LNK, 200 + ids[i]);
        }
        d->pos = 0;
        return (DIR *)d;
    }

    if (pi.cls == PATH_SYSFS_VIRT_DIR) {
        int ids[MAX_DEVICES];
        int count = query_device_list(ids);
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        for (int i = 0; i < count; i++) {
            char name[32];
            snprintf(name, sizeof(name), "input%d", ids[i]);
            fake_dir_add(d, name, DT_DIR, 300 + ids[i]);
        }
        d->pos = 0;
        return (DIR *)d;
    }

    if (pi.cls == PATH_SYSFS_INPUT && pi.remainder[0] == '\0') {
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        fake_dir_add(d, "name",         DT_REG, 400);
        fake_dir_add(d, "id",           DT_DIR, 401);
        fake_dir_add(d, "capabilities", DT_DIR, 402);
        fake_dir_add(d, "uevent",       DT_REG, 403);
        char evname[32];
        snprintf(evname, sizeof(evname), "event%d", pi.dev_id);
        fake_dir_add(d, evname,         DT_DIR, 404);
        d->pos = 0;
        return (DIR *)d;
    }

    if (pi.cls == PATH_SYSFS_INPUT && strcmp(pi.remainder, "id") == 0) {
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        fake_dir_add(d, "bustype", DT_REG, 410);
        fake_dir_add(d, "vendor",  DT_REG, 411);
        fake_dir_add(d, "product", DT_REG, 412);
        fake_dir_add(d, "version", DT_REG, 413);
        d->pos = 0;
        return (DIR *)d;
    }

    if (pi.cls == PATH_SYSFS_INPUT && strcmp(pi.remainder, "capabilities") == 0) {
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        fake_dir_add(d, "ev",  DT_REG, 420);
        fake_dir_add(d, "key", DT_REG, 421);
        fake_dir_add(d, "abs", DT_REG, 422);
        fake_dir_add(d, "rel", DT_REG, 423);
        fake_dir_add(d, "ff",  DT_REG, 424);
        fake_dir_add(d, "msc", DT_REG, 425);
        fake_dir_add(d, "sw",  DT_REG, 426);
        fake_dir_add(d, "led", DT_REG, 427);
        fake_dir_add(d, "snd", DT_REG, 428);
        d->pos = 0;
        return (DIR *)d;
    }

    if (pi.cls == PATH_SYSFS_EVENT && pi.remainder[0] == '\0') {
        struct fake_dir *d = make_fake_dir(path);
        if (!d) return NULL;
        fake_dir_add(d, "dev",    DT_REG, 430);
        fake_dir_add(d, "uevent", DT_REG, 431);
        d->pos = 0;
        return (DIR *)d;
    }

    errno = ENOENT;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* readdir / readdir64                                                */
/* ------------------------------------------------------------------ */

bool should_intercept_readdir(DIR *dirp) { return is_fake_dir(dirp); }

struct dirent *intercept_readdir(DIR *dirp) {
    struct fake_dir *d = (struct fake_dir *)dirp;
    dbg("readdir: path=%s", d->path);
    if (d->pos >= d->count) return NULL;
    return &d->entries[d->pos++];
}

struct dirent64 *intercept_readdir64(DIR *dirp) {
    struct fake_dir *d = (struct fake_dir *)dirp;
    dbg("readdir64: path=%s", d->path);
    if (d->pos >= d->count) return NULL;
    return &d->entries64[d->pos++];
}

/* ------------------------------------------------------------------ */
/* closedir / dirfd                                                   */
/* ------------------------------------------------------------------ */

bool should_intercept_closedir(DIR *dirp) { return is_fake_dir(dirp); }

int intercept_closedir(DIR *dirp) {
    struct fake_dir *d = (struct fake_dir *)dirp;
    dbg("closedir: path=%s", d->path);
    free(dirp);
    return 0;
}

bool should_intercept_dirfd(DIR *dirp) { return is_fake_dir(dirp); }

int intercept_dirfd(DIR *dirp) {
    struct fake_dir *d = (struct fake_dir *)dirp;
    dbg("dirfd: path=%s", d->path);
    return FAKE_DIRFD_SENTINEL;
}
