/* Offline test of text.c: one correction on a copy of traits.csv, one new row, one wrong-hash row. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <share.h>
static void logf_(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); putchar('\n'); }
typedef struct { const char *file; const char *key; const char *en; const char *sha256; int new_row; const char *bug; } SuucpText;
#define SUUCP_TEXT_TABLE
static const SuucpText g_text[] = {
    {"traits.csv", "L_TRAIT_DESC_CLOSURE", "TEST, with a comma and \"quotes\".", "7dd7980d78a3950919cfe96602ff5b3bc49e2cb9928f94d90360cca961c5add9", 0, "SU-T1"},
    {"traits.csv", "L_TEST_NEW_ROW", "New row text.", "", 1, "SU-T2"},
    {"traits.csv", "L_TRAIT_DESC_SEETH", "should be skipped", "0000", 0, "SU-T3"},
};
#define text_c_skip_typedef
static int all_on(const char *b) { (void)b; return 1; }
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef SUUCP_TEXT_TABLE
#include "text_gen.h"
#endif

#define MAX_FIELDS 32

/* Split one CSV line (no embedded newlines in these files) into fields; returns field count. Fields are copied
 * into buf (unescaped). */
static int csv_split(const char *line, size_t len, char *buf, char **fields)
{
    int n = 0; size_t i = 0; char *o = buf;
    while (i <= len && n < MAX_FIELDS) {
        fields[n++] = o;
        if (i < len && line[i] == '"') {
            i++;
            while (i < len) {
                if (line[i] == '"') { if (i + 1 < len && line[i + 1] == '"') { *o++ = '"'; i += 2; continue; } i++; break; }
                *o++ = line[i++];
            }
            while (i < len && line[i] != ',') i++;
        } else {
            while (i < len && line[i] != ',') *o++ = line[i++];
        }
        *o++ = 0;
        if (i >= len) break;
        i++;                                             /* skip the comma */
        if (i == len) { fields[n++] = o; *o++ = 0; break; }   /* trailing empty field */
    }
    return n;
}

static void csv_put(FILE *f, const char *s)
{
    if (strpbrk(s, ",\"\r\n")) {
        fputc('"', f);
        for (; *s; s++) { if (*s == '"') fputc('"', f); fputc(*s, f); }
        fputc('"', f);
    } else fputs(s, f);
}

static void sha256_hex(const char *s, char out[65])
{
    BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; UCHAR d[32]; int i;
    out[0] = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return;
    if (BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0) == 0) {
        BCryptHashData(h, (PUCHAR)s, (ULONG)strlen(s), 0);
        BCryptFinishHash(h, d, 32, 0);
        BCryptDestroyHash(h);
        for (i = 0; i < 32; i++) sprintf_s(out + 2 * i, 3, "%02x", d[i]);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
}

static char *read_all(const char *path, size_t *len)
{
    FILE *f; char *b; long n;
    if (fopen_s(&f, path, "rb") || !f) return NULL;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    b = (char *)malloc((size_t)n + 1);
    if (b) { *len = fread(b, 1, (size_t)n, f); b[*len] = 0; }
    fclose(f);
    return b;
}

static void remove_previous(const char *odir)
{
    char man[MAX_PATH], line[MAX_PATH], p[MAX_PATH]; FILE *f;
    _snprintf_s(man, sizeof man, _TRUNCATE, "%ssuucp_text.txt", odir);
    if (fopen_s(&f, man, "r") || !f) return;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] && !strchr(line, '\\') && !strchr(line, '/')) {
            _snprintf_s(p, sizeof p, _TRUNCATE, "%s%s", odir, line);
            DeleteFileA(p);
        }
    }
    fclose(f);
    DeleteFileA(man);
}

/* Build the override files for the enabled corrections. enabled(bug) tells whether a correction's bug is switched on. */
static void build_text_overrides(const char *gamedir, int (*enabled)(const char *bug))
{
    char odir[MAX_PATH], src[MAX_PATH], dst[MAX_PATH], man[MAX_PATH];
    int i, j, nt = (int)(sizeof g_text / sizeof g_text[0]), written = 0, skipped = 0;
    FILE *mf = NULL;
    _snprintf_s(odir, sizeof odir, _TRUNCATE, "%slocalization_override\\", gamedir);
    remove_previous(odir);
    if (nt == 0 || !g_text[0].file) { logf_("text: no corrections"); return; }
    CreateDirectoryA(odir, NULL);
    _snprintf_s(man, sizeof man, _TRUNCATE, "%ssuucp_text.txt", odir);
    for (i = 0; i < nt; i++) {                         /* one output file per distinct CSV, in table order */
        size_t len = 0; char *data; FILE *out = NULL; int dup = 0;
        for (j = 0; j < i; j++) if (strcmp(g_text[j].file, g_text[i].file) == 0) dup = 1;
        if (dup) continue;
        _snprintf_s(src, sizeof src, _TRUNCATE, "%slocalization\\%s", gamedir, g_text[i].file);
        data = read_all(src, &len);
        if (!data) { logf_("text: cannot read %s", src); continue; }
        for (j = i; j < nt; j++) {
            const SuucpText *t = &g_text[j];
            char *p = data + ((len >= 3 && (unsigned char)data[0] == 0xEF) ? 3 : 0), *eol, buf[16384], *fl[MAX_FIELDS];
            int found = 0, nf = 0, k;
            if (strcmp(t->file, g_text[i].file) || !enabled(t->bug)) continue;
            if (!out) {                                 /* header = first line of the original file */
                eol = strstr(p, "\r\n");
                _snprintf_s(dst, sizeof dst, _TRUNCATE, "%s%s", odir, t->file);
                if (fopen_s(&out, dst, "wb") || !out) { logf_("text: cannot write %s", dst); break; }
                fwrite("\xEF\xBB\xBF", 1, 3, out);
                fwrite(p, 1, (size_t)(eol ? eol - p : 0), out); fputs("\r\n", out);
                if (!mf && fopen_s(&mf, man, "w") == 0 && mf) {}
                if (mf) fprintf(mf, "%s\n", t->file);
            }
            for (; *p; p = eol ? eol + 2 : p + strlen(p)) {
                size_t kl = strlen(t->key);
                eol = strstr(p, "\r\n");
                if (strncmp(p, t->key, kl) == 0 && p[kl] == ',') {
                    size_t ll = eol ? (size_t)(eol - p) : strlen(p);
                    if (ll >= sizeof buf / 2) break;
                    nf = csv_split(p, ll, buf, fl); found = 1; break;
                }
                if (!eol) break;
            }
            if (!found && t->new_row) {                  /* missing row: English in every language column */
                fputs(t->key, out); fputs(",", out);
                for (k = 2; k < 17; k++) { fputc(',', out); csv_put(out, t->en); }
                fputs("\r\n", out); written++; logf_("text: %s %s added (new row)", t->bug, t->key); continue;
            }
            if (!found || nf < 3) { logf_("text: %s %s not found in %s, skipped", t->bug, t->key, t->file); skipped++; continue; }
            {
                char h[65]; sha256_hex(fl[2], h);
                if (_stricmp(h, t->sha256) != 0) {
                    logf_("text: %s %s English changed since the patch was written, skipped", t->bug, t->key);
                    skipped++; continue;
                }
            }
            for (k = 0; k < nf; k++) { if (k) fputc(',', out); csv_put(out, k == 2 ? t->en : fl[k]); }
            fputs("\r\n", out); written++;
        }
        if (out) fclose(out);
        free(data);
    }
    if (mf) fclose(mf);
    logf_("text: %d corrections written, %d skipped", written, skipped);
}
int main(int argc, char **argv) { build_text_overrides(argv[1], all_on); return 0; }
