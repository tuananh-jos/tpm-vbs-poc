@echo off
rem Usage: build.bat <path-to-TSS.MSR\TSS.CPP>
if "%~1"=="" (
    echo Usage: build.bat ^<path-to-TSS.MSR\TSS.CPP^>
    exit /b 1
)
set "TSS=%~1"

rem Find MSVC environment
set "VCVARS="
for %%Y in (2022 2019 18 17) do (
    for %%E in (Community Professional Enterprise) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat" (
            if not defined VCVARS set "VCVARS=C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat.
    exit /b 1
)
call "%VCVARS%" >nul

set CL_FLAGS=/nologo /std:c++17 /EHsc /MD /DWIN32 /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TSS%\include"
set LINK_FLAGS="%TSS%\bin\x64\Release\TSS.CPP.lib" ws2_32.lib

echo Building middle.exe ...
cl %CL_FLAGS% middle_main.cpp /Fe:middle.exe /link %LINK_FLAGS%
if %ERRORLEVEL% neq 0 ( echo BUILD FAILED: middle.exe & exit /b %ERRORLEVEL% )

echo Building external.exe ...
cl %CL_FLAGS% external_main.cpp /Fe:external.exe /link %LINK_FLAGS%
if %ERRORLEVEL% neq 0 ( echo BUILD FAILED: external.exe & exit /b %ERRORLEVEL% )

copy /Y "%TSS%\bin\x64\Release\TSS.CPP.dll" "%~dp0TSS.CPP.dll" >nul
echo.
echo BUILD OK
echo Run as Administrator:
echo   1. middle.exe   (start first -- owns TBS)
echo   2. external.exe (connect via named pipe)
