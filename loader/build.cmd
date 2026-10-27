@echo off
rem Builds version.dll (x64) from suucp.c. Needs Python (pefile) and MSVC Build Tools.
setlocal
cd /d "%~dp0"
python gen_patches.py || exit /b 1
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
if not exist build mkdir build
cl /nologo /O2 /W4 /MT /LD suucp.c /Fobuild\ /Febuild\version.dll /link /NOLOGO /DEF:suucp.def /MAP:build\version.map kernel32.lib || exit /b 1
copy /y suucp.ini build\suucp.ini >nul
echo built build\version.dll
