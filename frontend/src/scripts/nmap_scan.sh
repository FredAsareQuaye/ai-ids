#!/bin/bash

# Default values
SCAN_NAME="unnamed_scan"
VULN_SCAN=false

# Parse command line arguments
while getopts "t:n:v" opt; do
  case $opt in
    t) TARGETS="$OPTARG";;
    n) SCAN_NAME="$OPTARG";;
    v) VULN_SCAN=true;;
    \?) echo "Invalid option -$OPTARG" >&2; exit 1;;
  esac
done

# Base nmap command with default options
NMAP_CMD="nmap -sT -sV -T5 -vv"

# Add vulnerability scripts if requested
if [ "$VULN_SCAN" = true ]; then
    NMAP_CMD="$NMAP_CMD --script=vuln"
fi

# Add output file
NMAP_CMD="$NMAP_CMD -oX \"$SCAN_NAME.xml\""

# Add targets
NMAP_CMD="$NMAP_CMD $TARGETS"

# Save the actual command to a file for the UI to display
echo "$NMAP_CMD" > "$HOME/.siem_scan_cmd.txt"

# Run the scan and capture all output
echo "Running command: $NMAP_CMD" > "$HOME/.siem_scan_output.log"
echo "Target: $TARGETS" >> "$HOME/.siem_scan_output.log"
echo "Timestamp: $(date)" >> "$HOME/.siem_scan_output.log"
echo "-------------------------------------------" >> "$HOME/.siem_scan_output.log"

# Execute the command and capture all output
eval $NMAP_CMD 2>&1 | tee -a "$HOME/.siem_scan_output.log"
SCAN_EXIT_CODE=${PIPESTATUS[0]}

# Check if scan was successful
if [ $SCAN_EXIT_CODE -eq 0 ]; then
    echo "\nScan completed successfully. Results saved to $SCAN_NAME.xml" >> "$HOME/.siem_scan_output.log"
    exit 0
else
    echo "\nScan failed with exit code $SCAN_EXIT_CODE" >> "$HOME/.siem_scan_output.log"
    exit 1
fi
