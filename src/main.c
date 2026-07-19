#include "hipa_secfile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *read_stream(FILE *f, size_t *len)
{
    size_t cap = 1 << 16, n = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (n + (1 << 16) > cap) {
            cap *= 2;
            char *nb = (char *)realloc(buf, cap);
            if (!nb) { free(buf); return NULL; }
            buf = nb;
        }
        size_t got = fread(buf + n, 1, 1 << 16, f);
        n += got;
        if (got < (1 << 16)) break;
    }
    char *fb = (char *)realloc(buf, n + 1);
    if (fb) buf = fb;
    buf[n] = '\0';
    *len = n;
    return buf;
}

static char *read_input(const char *path, size_t *len)
{
    if (!path || strcmp(path, "-") == 0)
        return read_stream(stdin, len);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = read_stream(f, len);
    fclose(f);
    return buf;
}

static int usage(const char *prog)
{
    fprintf(stderr,
        "usage:\n"
        "  %s [input.raw|-] [output.xml]\n"
        "  %s --hash <keyname> [channel]\n"
        "\n"
        "  input defaults to stdin, output to stdout:\n"
        "  curl '.../query_security_file?file_key=PC' | %s > config.xml\n",
        prog, prog, prog);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--hash") == 0) {
        if (argc < 3) return usage(argv[0]);
        uint32_t channel = 0x12345678u;
        if (argc >= 4) channel = (uint32_t)strtoul(argv[3], NULL, 0);
        printf("%u\n", hipa_key_hash(argv[2], channel));
        return 0;
    }

    const char *in_path = (argc >= 2) ? argv[1] : NULL;
    const char *out_path = (argc >= 3) ? argv[2] : NULL;

    if (!in_path && isatty(fileno(stdin))) return usage(argv[0]);

    size_t raw_len = 0;
    char *raw = read_input(in_path, &raw_len);
    if (!raw) {
        fprintf(stderr, "error: cannot read %s\n", in_path ? in_path : "stdin");
        return 1;
    }

    uint8_t *out = NULL;
    size_t out_len = 0;
    hipa_status st = hipa_decrypt(raw, raw_len, &out, &out_len);
    free(raw);
    if (st != HIPA_OK) {
        fprintf(stderr, "error: %s\n", hipa_strerror(st));
        return 1;
    }

    if (out_path) {
        FILE *f = fopen(out_path, "wb");
        if (!f) { fprintf(stderr, "error: cannot write %s\n", out_path); free(out); return 1; }
        fwrite(out, 1, out_len, f);
        fclose(f);
        fprintf(stderr, "decrypted %zu bytes -> %s\n", out_len, out_path);
    } else {
        fwrite(out, 1, out_len, stdout);
    }
    free(out);
    return 0;
}
