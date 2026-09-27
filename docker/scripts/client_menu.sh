#!/bin/sh

show_menu() {
    clear
    echo "=========================================="
    echo "       CLIENT SIMULATOR          "
    echo "=========================================="
    echo " 1) Start Normal Traffic"
    echo " 2) Stop Normal Traffic"
    echo " 0) Exit"
    echo "=========================================="
    printf "Select an option [0-2]: "
}

stop_traffic() {
    echo "Stopping normal traffic..."
    killall -9 client_simulator.sh 2>/dev/null
    killall -9 sleep 2>/dev/null
    killall -9 curl 2>/dev/null
    echo "Traffic stopped."
}

while true; do
    show_menu
    read choice
    case "$choice" in
        1)
            stop_traffic
            echo "Starting normal traffic in background..."
            /bin/sh /scripts/client_simulator.sh > /dev/null 2>&1 &
            echo "Traffic is running. Press Enter to continue."
            read dummy
            ;;
        2)
            stop_traffic
            echo "Press Enter to continue."
            read dummy
            ;;
        0)
            stop_traffic
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option. Press Enter to continue."
            read dummy
            ;;
    esac
done
