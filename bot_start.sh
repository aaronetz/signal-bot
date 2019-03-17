#!/bin/bash
if pgrep -f signal-bot > /dev/null 
then
    echo "Bot already running. Please stop first."
    exit 1
fi

echo "Starting listener, logs will be saved under ./log" 
nohup build/install/signal-bot/bin/signal-bot --listen 2>&1 | multilog s1000000 n10 ./log &
