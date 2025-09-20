#!/bin/bash
set +m  # hide job control messages

# Spinner function
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        for i in $(seq 0 3); do
            printf "\r[%c] Loading..." "${spinstr:$i:1}"
            sleep $delay
        done
    done
    printf "\r"
}

# Run command with spinner
run_with_spinner() {
    "$@" >/dev/null 2>&1 &
    spinner $!
    wait $!
}

# Main tasks
run_with_spinner python3 -m venv scanner
source scanner/bin/activate
run_with_spinner pip install --upgrade pip
run_with_spinner pip install python-nmap PyQt5 cryptography requests
python3 Cyber_Expert_Bladex_v3.py
