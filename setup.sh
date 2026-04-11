#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1}" == "--host" ]]; then
    cd "$SCRIPT_DIR"
    sudo apt-get install -y jq python3-pip python3-matplotlib python3-pandas python3-seaborn
    git config --local url."https://github.com/".insteadOf "git@github.com:"
    git submodule sync --recursive
    git submodule update --init --recursive
    for dir in librebound cmd/prod-server cmd/simple-server bench/microbench; do
        (cd "$SCRIPT_DIR/$dir" && go mod tidy)
    done
else
    export REBOUND_HOME=/rebound
    cd "$REBOUND_HOME"
    mkdir -p o
    rm -f /etc/apt/sources.list.d/yarn.list
    apt update
    apt -y install python3-pip
    apt -y install python3-matplotlib python3-pandas python3-seaborn
fi
