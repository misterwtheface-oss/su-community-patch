/* Offline test of text.c with the generated table (text_gen.h): builds localization_override from a copy of the
 * installed localization folder given as argv[1] (a folder containing localization\). Run from loader/test. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <share.h>
static void logf_(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vprintf(fmt, ap); va_end(ap); putchar('\n'); }
static int all_on(const char *b) { (void)b; return 1; }
#include "../text.c"
int main(int argc, char **argv)
{
    char dir[MAX_PATH];
    if (argc < 2) return 2;
    _snprintf_s(dir, sizeof dir, _TRUNCATE, "%s\\", argv[1]);
    build_text_overrides(dir, all_on);
    return 0;
}
