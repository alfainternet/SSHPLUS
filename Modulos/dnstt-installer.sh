#!/bin/bash

BIN_NAME="dnstt-manager"
BIN_PATH="/usr/local/bin/$BIN_NAME"
BIN_URL="https://raw.githubusercontent.com/alfainternet/SSHPLUS/master/Modulos/$BIN_NAME"

clear

if [ -f "$BIN_PATH" ]; then
    echo "[!] $BIN_NAME já está instalado. Removendo para reinstalar..."
    sudo rm -f "$BIN_PATH"
fi

echo "[+] Baixando $BIN_NAME..."
curl -sSL "$BIN_URL" -o "$BIN_NAME"

if [ ! -f "$BIN_NAME" ]; then
    echo "[ERRO] Falha ao baixar o binário."
    exit 1
fi

chmod +x "$BIN_NAME"
sudo mv "$BIN_NAME" "$BIN_PATH"

echo "[✔] Instalação completa! Você pode executar com:"
echo "     dnstt-manager"
