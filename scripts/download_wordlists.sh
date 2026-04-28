#!/usr/bin/env bash
# download_wordlists.sh — Download optional large wordlists
# rockyou.txt is too large for Git (130MB+) and is excluded via .gitignore.
# Run this script once to download it into cracker/wordlists/.

set -e

WORDLIST_DIR="$(dirname "$0")/../cracker/wordlists"
ROCKYOU_URL="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
ROCKYOU_PATH="$WORDLIST_DIR/rockyou.txt"

echo "[*] Downloading rockyou.txt (~130MB)..."
curl -L "$ROCKYOU_URL" -o "$ROCKYOU_PATH"
echo "[✓] Saved to $ROCKYOU_PATH"
echo "[*] Usage: python3 main.py dict <hash> -w cracker/wordlists/rockyou.txt"
