:: This script must not rely on any external tools or PATH values.
@echo OFF

:: Let advanced users checkout the tools in just one P4 enlistment
if "%SETUP_ENV_SETUPTOOLS%"=="done" goto :EOF
set "%SETUP_ENV_SETUPTOOLS=done

:: Add the setuptools egg to PYTHONPATH
set PYTHONPATH=%PYTHONPATH%;%~dp0\setuptools-0.6c11-py2.6.egg
