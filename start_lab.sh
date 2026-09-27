#!/bin/bash

# Prevent running the entire script with sudo to avoid breaking GUI popups
if [ "$EUID" -eq 0 ]; then
  echo "[!] ERROR: Do NOT run this script with sudo!"
  echo "         Running GUI applications via sudo breaks display permissions (dbus-launch)."
  echo "         Please run it normally: ./start_lab.sh"
  echo "         (The script will automatically request sudo for Docker if needed)."
  exit 1
fi

# Determine if docker needs sudo
if docker info >/dev/null 2>&1; then
    DOCKER_CMD="docker"
else
    DOCKER_CMD="sudo docker"
fi

echo "=============================================="
echo "  Docker Lab Automation Setup"
echo "=============================================="
echo "Starting Docker Compose..."

cd docker
if ! $DOCKER_CMD compose up -d --build; then
    echo "[!] Docker Compose failed to start. Exiting."
    exit 1
fi

echo ""
echo "Launching AI Forecast Dashboard and Attacker Console..."

if command -v gnome-terminal &> /dev/null; then
    gnome-terminal --geometry=160x45 --window --title="AI Forecast Dashboard" -e "bash -c \"$DOCKER_CMD exec -e TERM=xterm-256color -it forecast bash -c 'python3 network_traffic_collector/main.py --ml'; exec bash\""
    gnome-terminal --geometry=100x30 --window --title="SIH Attacker Menu" -e "bash -c \"$DOCKER_CMD exec -e TERM=xterm-256color -it attacker bash /scripts/attack_menu.sh; exec bash\""
elif command -v konsole &> /dev/null; then
    konsole -e bash -c "$DOCKER_CMD exec -e TERM=xterm-256color -it forecast bash -c 'python3 network_traffic_collector/main.py --ml'; exec bash" &
    konsole -e bash -c "$DOCKER_CMD exec -e TERM=xterm-256color -it attacker bash /scripts/attack_menu.sh; exec bash" &
elif command -v xterm &> /dev/null; then
    # xterm does not support tabs, so they will still open in separate windows
    xterm -geometry 160x45 -title "AI Forecast Dashboard" -e "$DOCKER_CMD exec -e TERM=xterm-256color -it forecast bash -c 'python3 network_traffic_collector/main.py --ml'; bash" &
    xterm -geometry 100x30 -title "SIH Attacker Menu" -e "$DOCKER_CMD exec -e TERM=xterm-256color -it attacker bash /scripts/attack_menu.sh; bash" &
else
    echo "[!] No supported terminal emulator found (gnome-terminal, konsole, xterm)."
    echo "Please open three new terminal windows and manually run:"
    echo "  1. $DOCKER_CMD exec -it forecast bash -c 'python3 network_traffic_collector/main.py --ml'"
    echo "  2. $DOCKER_CMD exec -it attacker bash /scripts/attack_menu.sh"
fi

echo ""
echo "All services are running!"
echo "Check the new popup windows for the AI Dashboard and the Attack Menu."
echo "Press Enter to safely stop and tear down the lab..."
read

$DOCKER_CMD compose stop
echo "Lab stopped successfully. Containers are preserved."
