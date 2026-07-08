#!/bin/bash
cargo test -p iw-warden --test evasion_test &
PID=$!
sleep 2
gdb -p $PID -batch -ex "thread apply all bt" > gdb_trace.txt
kill -9 $PID
