@echo off
rem Usage: build.bat <path-to-TSS.MSR\TSS.CPP>
rem Example: build.bat C:\dev\TSS.MSR\TSS.CPP
if "%~1"=="" (
    echo Usage: build.bat ^<path-to-TSS.MSR\TSS.CPP^>
    echo Example: build.bat C:\dev\TSS.MSR\TSS.CPP
    exit /b 1
)
set "TSS=%~1"

rem Find and load MSVC environment (tries VS 2022 then VS 2019)
set "VCVARS="
for %%Y in (2022 2019) do (
    for %%E in (Community Professional Enterprise) do (
        if exist "C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat" (
            if not defined VCVARS set "VCVARS=C:\Program Files\Microsoft Visual Studio\%%Y\%%E\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)
if not defined VCVARS (
    echo ERROR: Could not find vcvars64.bat. Install Visual Studio 2019 or 2022.
    exit /b 1
)
call "%VCVARS%" >nul

rem /DWIN32: TSS.CPP's fdefs.h gates <windows.h> (BYTE/UINT32/SOCKET) on WIN32,
rem which the VS project defines but the command-line cl does not (it only sets _WIN32).
cl /nologo /std:c++17 /EHsc /MD /DWIN32 /D_WINSOCK_DEPRECATED_NO_WARNINGS ^
   /I"%TSS%\include" vbs_poc.cpp ^
   /Fe:vbs_poc.exe ^
   /link "%TSS%\bin\x64\Release\TSS.CPP.lib" ws2_32.lib
if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED.
    exit /b %ERRORLEVEL%
)

rem TSS.CPP.dll must sit next to the exe at runtime.
copy /Y "%TSS%\bin\x64\Release\TSS.CPP.dll" "%~dp0TSS.CPP.dll" >nul
echo BUILD OK -- vbs_poc.exe ready.
