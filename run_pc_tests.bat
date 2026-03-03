@echo off
echo Compiling...
cl /EHsc /I src/include pc_main.cpp src/source/*.cpp src/tests/*.cpp /Fe:pqc_tests.exe
if errorlevel 1 goto :fail
echo Running...
pqc_tests.exe
goto :end
:fail
echo.
echo [ERROR] FAILED. Is Visual Studio installed and in PATH?
:end
pause
