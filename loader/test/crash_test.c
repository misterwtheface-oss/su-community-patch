/* Loads build/version.dll, then faults once inside __try: the loader's crash logger must record it in suucp.log
 * (and must not swallow it: our own __except still runs). */
#include <windows.h>
#include <stdio.h>
int main(void)
{
    volatile int *p = NULL;
    if (!LoadLibraryW(L"../build/version.dll")) { printf("load failed\n"); return 1; }
    __try { *p = 1; } __except (EXCEPTION_EXECUTE_HANDLER) { printf("own handler still ran\n"); }
    return 0;
}
