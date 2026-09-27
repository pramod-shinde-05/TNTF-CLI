#!/bin/bash

# Check if zenity is installed (common on Linux desktop environments)
if ! command -v zenity &> /dev/null; then
    echo "Zenity is not installed. Using text prompt instead."
    echo -n "Enter the full path to the PCAP or CSV file: "
    read FILE_PATH
else
    echo "Opening file explorer to select a PCAP or CSV file..."
    FILE_PATH=$(zenity --file-selection --title="Select PCAP or CSV file to analyze" --file-filter="Network Files | *.pcap *.pcapng *.csv" --file-filter="All Files | *")
fi

if [ -z "$FILE_PATH" ]; then
    echo "No file selected. Exiting."
    exit 0
fi

if [ ! -f "$FILE_PATH" ]; then
    echo "File does not exist: $FILE_PATH"
    exit 1
fi

FILENAME=$(basename "$FILE_PATH")
echo "Selected file: $FILE_PATH"
echo "Uploading to forecast container..."

# Copy the file into the forecast container at /home/
sudo docker cp "$FILE_PATH" forecast:"/home/$FILENAME"

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Successfully uploaded $FILENAME to /home/ inside the forecast container."
    echo "You can now use the 'Analyze File' option in the Terminal Dashboard to select it!"
else
    echo "❌ Failed to upload file to container. Is the forecast container running?"
fi
