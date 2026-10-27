// R7: main pengganti libFuzzer. "regr_X file|dir ..." menjalankan tiap input
// sekali (buffer seukuran persis, jadi ASan menangkap baca lewat batas);
// "regr_X -s DIR" menulis korpus awal. Tidak butuh libFuzzer (gcc juga bisa).

#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include "fuzz.h"

static int g_runs;

static void run_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "fuzz: tidak bisa membuka %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(n > 0 ? (size_t)n : 1);
    if (n > 0 && fread(b, 1, (size_t)n, f) != (size_t)n) {
        exit(2);
    }
    fclose(f);
    LLVMFuzzerTestOneInput(b, (size_t)n);
    free(b);
    g_runs++;
}

static void run_path(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return;   // direktori korpus opsional boleh belum ada
    }
    if (!S_ISDIR(st.st_mode)) {
        run_file(path);
        return;
    }
    DIR *d = opendir(path);
    struct dirent *e;
    while (d && (e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.') {
            char p[1024];
            snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
            run_path(p);
        }
    }
    if (d) {
        closedir(d);
    }
}

int main(int argc, char **argv)
{
    LLVMFuzzerInitialize(&argc, &argv);
    if (argc == 3 && strcmp(argv[1], "-s") == 0) {
        fuzz_seeds(argv[2]);
        return 0;
    }
    for (int i = 1; i < argc; i++) {
        run_path(argv[i]);
    }
    const char *name = strrchr(argv[0], '/');
    printf("%-12s %d input fuzz lulus\n", name ? name + 1 : argv[0], g_runs);
    return 0;
}
