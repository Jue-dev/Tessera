@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0export_sdk.ps1" %*
