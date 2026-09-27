@echo off
setlocal

echo Opening file explorer to select a PCAP or CSV file...

:: Use PowerShell to open a native Windows file selection dialog
for /f "delims=" %%I in ('powershell -NoProfile -Command "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.Filter = 'Network Files (*.pcap;*.pcapng;*.csv)|*.pcap;*.pcapng;*.csv|All Files (*.*)|*.*'; $f.Title = 'Select PCAP or CSV file to analyze'; $f.ShowHelp = $true; if ($f.ShowDialog() -eq 'OK') { $f.FileName }"') do set "FILE_PATH=%%I"

if "%FILE_PATH%"=="" (
    echo No file selected. Exiting.
    pause
    exit /b
)

echo Selected file: %FILE_PATH%
echo Uploading to forecast container...

:: Extract filename from path
for %%F in ("%FILE_PATH%") do set "FILENAME=%%~nxF"

docker cp "%FILE_PATH%" forecast:"/home/%FILENAME%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [SUCCESS] Uploaded %FILENAME% to /home/ inside the forecast container.
    echo You can now use the 'Analyze File' option in the Terminal Dashboard to select it!
) else (
    echo [ERROR] Failed to upload file to container. Is the forecast container running?
)

pause
