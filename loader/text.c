/* Text corrections, shipped through the game's own localization_override folder.
 *
 * scr_LanguageImport reads localization\*.csv and then localization_override\*.csv. At startup (before the game
 * loads its text) we build override files from the player's OWN installed CSVs: for each correction we find the row,
 * check its English against the hash it was written for (a changed description is skipped and logged), replace only
 * the English column and copy every other column unchanged. No game text ships with the patch.
 * Files we generate are listed in localization_override\suucp_text.txt and removed before each rebuild.
 * Included by suucp.c. */

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

/* en = the new English line, or (when find is set) the text that replaces the fragment `find` in the installed line,
 * so long texts (Codex entries) are corrected without storing them. */
typedef struct { const char *file; const char *key; const char *en; const char *sha256; int new_row; const char *bug; const char *copy_from; const char *find; } SuucpText;
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
            char *p = data + ((len >= 3 && (unsigned char)data[0] == 0xEF) ? 3 : 0), *eol, *fl[MAX_FIELDS];
            static char buf[262144];                    /* one CSV row (Codex rows in 15 languages run past 8 KB) */
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
                const char *want = (t->new_row && t->copy_from && t->copy_from[0]) ? t->copy_from : t->key;
                size_t kl = strlen(want);
                eol = strstr(p, "\r\n");
                if (strncmp(p, want, kl) == 0 && p[kl] == ',') {
                    size_t ll = eol ? (size_t)(eol - p) : strlen(p);
                    if (ll >= sizeof buf / 2) break;
                    nf = csv_split(p, ll, buf, fl); found = 1; break;
                }
                if (!eol) break;
            }
            if (found && t->new_row && nf >= 3) {        /* new row modelled on copy_from: its other languages */
                fputs(t->key, out); fputs(",", out);
                for (k = 2; k < nf; k++) { fputc(',', out); csv_put(out, k == 2 ? t->en : fl[k]); }
                fputs("\r\n", out); written++; logf_("text: %s %s added (languages from %s)", t->bug, t->key, t->copy_from);
                continue;
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
            {
                const char *en = t->en;
                static char edited[65536];
                if (t->find && t->find[0]) {                 /* fragment edit of the installed English */
                    const char *at = strstr(fl[2], t->find);
                    size_t pre, fln, el;
                    if (!at) { logf_("text: %s %s fragment not found, skipped", t->bug, t->key); skipped++; continue; }
                    pre = (size_t)(at - fl[2]); fln = strlen(t->find); el = strlen(t->en);
                    if (pre + el + strlen(at + fln) + 1 > sizeof edited) { skipped++; continue; }
                    memcpy(edited, fl[2], pre); memcpy(edited + pre, t->en, el);
                    strcpy_s(edited + pre + el, sizeof edited - pre - el, at + fln);
                    en = edited;
                }
                for (k = 0; k < nf; k++) { if (k) fputc(',', out); csv_put(out, k == 2 ? en : fl[k]); }
            }
            fputs("\r\n", out); written++;
        }
        if (out) fclose(out);
        free(data);
    }
    if (mf) fclose(mf);
    logf_("text: %d corrections written, %d skipped", written, skipped);
}
