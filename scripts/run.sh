#!/bin/sh
# Invoke the on-device akane-injector with whatever args you pass through.
#   scripts/run.sh -p <pid> -s /data/local/tmp/your.so
exec adb shell su -c "/data/local/tmp/akane-injector $*"
