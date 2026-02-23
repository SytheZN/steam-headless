#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (access("/.container", F_OK) != 0) {
        fprintf(stderr, "uinput-install: refusing to run outside a container (/.container not found)\n");
        return 1;
    }
    if (access("/dev/uinput", F_OK) == 0) {
        fprintf(stderr, "uinput-install: refusing to run with real /dev/uinput present\n");
        return 1;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <uinput-path> <library-name>\n", argv[0]);
        return 1;
    }

    const char *uinput_path = argv[1];
    const char *lib_name = argv[2];

    /* Verify the path is reasonable (basic sanity check) */
    if (strlen(uinput_path) == 0 || strlen(uinput_path) > 4096) {
        fprintf(stderr, "Error: Invalid path length\n");
        return 1;
    }

    /* Construct paths to verify .so files exist */
    char lib64_path[4096];
    char lib_path[4096];

    snprintf(lib64_path, sizeof(lib64_path), "%s/lib64/%s", uinput_path, lib_name);
    snprintf(lib_path, sizeof(lib_path), "%s/lib/%s", uinput_path, lib_name);

    struct stat st;
    int has_lib64 = (stat(lib64_path, &st) == 0);
    int has_lib = (stat(lib_path, &st) == 0);

    if (!has_lib64 && !has_lib) {
        fprintf(stderr, "Error: No %s found at %s/lib64/ or %s/lib/\n",
                lib_name, uinput_path, uinput_path);
        return 1;
    }

    /* Construct the preload line */
    char preload_line[4096];
    snprintf(preload_line, sizeof(preload_line), "%s/$LIB/%s\n", uinput_path, lib_name);

    /* Open /etc/ld.so.preload for appending */
    FILE *fp = fopen("/etc/ld.so.preload", "a");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open /etc/ld.so.preload: %s\n", strerror(errno));
        return 1;
    }

    /* Write the line */
    if (fputs(preload_line, fp) == EOF) {
        fprintf(stderr, "Error: Cannot write to /etc/ld.so.preload: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    }

    fclose(fp);

    /* Output the LD_PRELOAD export for the caller to source */
    printf("export LD_PRELOAD='%s/$LIB/%s'\n", uinput_path, lib_name);

    return 0;
}
