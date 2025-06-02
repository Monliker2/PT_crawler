#!/bin/bash

WATCH_FOLDER="/var/mail"

inotifywait -m -e modify --format '%w%f' "$WATCH_FOLDER" | while read -r FILE; do
    if [[ -f "$FILE" ]]; then
        echo "File changed: $FILE"

        LAST_EMAIL=$(tac "$FILE" | awk 'BEGIN {capture=1} /^From / {capture=0} capture==1 {print $0}' | tac)

        echo "$LAST_EMAIL" | grep -oP 'https?://[^\s/$.?#].[^\s]*(:\d+)?' | while read -r LINK; do
            echo "Processing link: $LINK"
            python3 /home/user/PT_crawler/main.py "$LINK"
        done
    fi
done
