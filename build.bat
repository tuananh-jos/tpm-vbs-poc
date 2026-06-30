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
for %%Y in (2022 2019 18 17) do (
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

rem /DWIN32: TSS.CPP's fdefs.h gates <windows.h> (BYTE/UINT32/SOCKET) on WIN32.
set CL_FLAGS=/nologo /std:c++17 /EHsc /MD /DWIN32 /D_WINSOCK_DEPRECATED_NO_WARNINGS /I"%TSS%\include"
set LINK_FLAGS="%TSS%\bin\x64\Release\TSS.CPP.lib" ws2_32.lib

rem --- 1. Build enclave DLL (VTL1) -------------------------------------------
echo Building enclave DLL...
cl %CL_FLAGS% enclave\tpm_enclave.cpp /LD /Fe:tpm_enclave.dll ^
   /link %LINK_FLAGS% /ENCLAVE
if %ERRORLEVEL% neq 0 ( echo ENCLAVE BUILD FAILED. & exit /b %ERRORLEVEL% )
echo Enclave DLL: tpm_enclave.dll

rem --- 2. Build host EXE (VTL0) -----------------------------------------------
echo Building host EXE...
cl %CL_FLAGS% vbs_poc.cpp /Fe:vbs_poc.exe ^
   /link %LINK_FLAGS% onecore.lib
if %ERRORLEVEL% neq 0 ( echo HOST BUILD FAILED. & exit /b %ERRORLEVEL% )

rem TSS.CPP.dll must sit next to the exe at runtime.
copy /Y "%TSS%\bin\x64\Release\TSS.CPP.dll" "%~dp0TSS.CPP.dll" >nul
echo BUILD OK -- vbs_poc.exe + tpm_enclave.dll ready.
echo.
echo Usage:
echo   vbs_poc.exe               -- simulator (default)
echo   vbs_poc.exe --real-tpm    -- hardware TPM via TBS
echo   vbs_poc.exe --vbs-enclave -- VBS Enclave (VTL1, requires Hyper-V + Admin)
