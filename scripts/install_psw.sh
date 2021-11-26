#!/usr/bin/env bash


# delete old installer
rm -rf /tmp/libsgx-enclave-common_*_amd64.deb
rm -rf /tmp/libsgx-enclave-common-dbgsym_*_amd64.ddeb

# remove old psw
sudo dpkg -r libsgx-enclave-common
sudo dpkg -r libsgx-enclave-common-dbgsym

# copy new installer to tmp
cp linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common_*_amd64.deb /tmp
cp linux/installer/deb/libsgx-enclave-common/libsgx-enclave-common-dbgsym_*_amd64.ddeb /tmp

# install new psw
pushd /tmp
sudo dpkg -i libsgx-enclave-common_*_amd64.deb
sudo dpkg -i libsgx-enclave-common-dbgsym_*_amd64.ddeb
popd
