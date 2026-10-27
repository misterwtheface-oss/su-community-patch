/* Loads build/version.dll into a non-game exe: the loader must refuse to patch, and the version.dll functions must
 * pass through to System32. Run from loader/test. */
#include <windows.h>
#include <stdio.h>

int main(void)
{
    typedef DWORD (WINAPI *size_fn)(LPCWSTR, LPDWORD);
    HMODULE m = LoadLibraryW(L"../build/version.dll");
    DWORD h = 0, n;
    size_fn f;
    if (!m) { printf("load failed %lu\n", GetLastError()); return 1; }
    f = (size_fn)GetProcAddress(m, "GetFileVersionInfoSizeW");
    if (!f) { printf("export missing\n"); return 1; }
    n = f(L"C:/Windows/System32/kernel32.dll", &h);
    printf("GetFileVersionInfoSizeW(kernel32) = %lu\n", n);
    return n ? 0 : 1;
}
