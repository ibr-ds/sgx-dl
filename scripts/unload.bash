#!/usr/bin/env bash

sudo systemctl stop aesmd
sudo rmmod isgx
sudo modprobe isgx
sudo systemctl start aesmd
