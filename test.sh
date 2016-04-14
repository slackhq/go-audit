#!/bin/sh

export GOPATH="/home/ubuntu"
go build

stuff() {
    for i in $(seq 1 40000); do
        ls -l > /dev/null
    done
}

logger "STARTING"
stuff &

START=$(date +%s.%N)
./go-audit-new --cpuprofile
END=$(date +%s.%N)

echo $START
echo $END

echo "$END - $START" | bc

logger "STOPPING"
