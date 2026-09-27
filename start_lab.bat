@echo off
echo ==============================================
echo  Docker Lab Automation Setup
echo ==============================================
echo Starting Docker Compose...
cd docker
docker compose up -d --build
if %errorlevel% neq 0 (
    echo [!] Docker Compose failed to start. Exiting.
    pause
    exit /b 1
)

echo.
echo Launching AI Forecast Dashboard and Attacker Console...
where wt >nul 2>&1
if %errorlevel% equ 0 goto use_wt

:use_cmd
start "AI Forecast Dashboard" cmd /c "mode con cols=160 lines=45 & docker exec -e TERM=xterm-256color -e COLORTERM=truecolor -it forecast bash -c \"python3 network_traffic_collector/main.py --ml\""
start "SIH Attacker Menu" cmd /c "mode con cols=100 lines=30 & docker exec -e TERM=xterm-256color -e COLORTERM=truecolor -it attacker bash /scripts/attack_menu.sh"
goto post_launch

:use_wt
start wt -w new --size 160,45 --title "AI Forecast Dashboard" cmd /c "docker exec -e TERM=xterm-256color -e COLORTERM=truecolor -it forecast bash -c \"python3 network_traffic_collector/main.py --ml\"" ";" new-tab --title "SIH Attacker Menu" cmd /c "docker exec -e TERM=xterm-256color -e COLORTERM=truecolor -it attacker bash /scripts/attack_menu.sh"

:post_launch
echo.
echo All services are running!
echo Check the new popup windows for the AI Dashboard and the Attack Menu.
echo Press any key to safely stop and tear down the lab...
pause
docker compose stop
echo Lab stopped successfully. Containers are preserved.
