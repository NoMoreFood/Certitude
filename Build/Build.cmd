@ECHO OFF

REM
REM Copyright (c) Bryan Berns.
REM Licensed under GPLv3. See LICENSE.md.
REM

SETLOCAL

REM Configure the release name and code-signing timestamp service.
SET TSAURL=http://time.certum.pl/
SET LIBNAME=Certitude

REM Resolve build, output, and staging folders relative to this launcher.
SET BASEDIR=%~dp0.
SET BINDIR=%~dp0..\Code\bin\Release
SET OUTDIR=%~dp0..\Binaries
SET STAGEDIR=%~dp0PackageStage

REM Run the build-and-sign pipeline and return its exit code to the caller.
POWERSHELL -NoProfile -File "%BASEDIR%\Build.ps1" -BinaryDirectory "%BINDIR%" ^
    -OutputDirectory "%OUTDIR%" -StageDirectory "%STAGEDIR%" ^
    -TimestampUrl "%TSAURL%" -ProductName "%LIBNAME%"
EXIT /B %ERRORLEVEL%
