@echo off
echo Compiling Cyber Toolkit...

:: Compilation command
gcc -o cyber_toolkit.exe cyber_toolkit.c port_scanner.c password_cracker.c dns_lookup.c common.c -lws2_32 -ldnsapi -lcrypto -lssl

:: Check if compilation was successful
if %ERRORLEVEL% equ 0 (
    echo Compilation successful! Executable created: cyber_toolkit.exe
    echo Running Cyber Toolkit...
    cyber_toolkit.exe
) else (
    echo Compilation failed! Please check for errors.
)

pause