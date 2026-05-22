#!/bin/bash
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true

    if [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -gt 1 ] && systemctl is-active --quiet arcmilter; then
        systemctl restart arcmilter >/dev/null 2>&1 || true
    fi
fi
