#!/bin/bash

chmod +x /start.sh
chmod +x /usr/bin/*
chmod +x /usr/bin/steamos-polkit-helpers/*

mkdir -p /etc/gamescope/scripts

setcap cap_sys_nice+ep /usr/bin/gamescope

mkdir -p /run/dbus
chown steam:steam /run/dbus