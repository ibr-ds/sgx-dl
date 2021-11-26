#!/usr/bin/env bash

# delete old installer
rm -rf /tmp/sgx_linux_x64_sdk_*.bin

# delete old sdk
sudo /opt/intel/sgxsdk/uninstall.sh

# copy new installer to tmp
cp linux/installer/bin/sgx_linux_x64_sdk_*.bin /tmp

# run new installer
pushd /tmp
sudo ./sgx_linux_x64_sdk_*.bin <<EOF
n
/opt/intel
EOF
popd
