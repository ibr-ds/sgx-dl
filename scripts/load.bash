#!/usr/bin/env bash

make
sudo systemctl stop aesmd
sudo rmmod isgx
cp isgx.ko /tmp/isgx.ko
sudo insmod /tmp/isgx.ko
sudo systemctl start aesmd

lsmod | grep isgx
