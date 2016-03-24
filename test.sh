#!/bin/sh

export GOPATH="/home/nate"
go build
./go-audit &

sleep 5

START=$(date +%s.%N)
for i in $(seq 1 40000); do
    ls -l > /dev/null
done
END=$(date +%s.%N)

echo $START
echo $END

killall go-audit

#RUN1
#1120ms of 2210ms total (50.68%)
#Dropped 57 nodes (cum <= 11.05ms)
#Showing top 10 nodes out of 151 (cum >= 40ms)
#      flat  flat%   sum%        cum   cum%
#     250ms 11.31% 11.31%      250ms 11.31%  runtime.epollwait
#     170ms  7.69% 19.00%      380ms 17.19%  runtime.mallocgc
#     170ms  7.69% 26.70%      210ms  9.50%  syscall.Syscall6
#     120ms  5.43% 32.13%      120ms  5.43%  runtime.memclr
#     100ms  4.52% 36.65%      100ms  4.52%  runtime._ExternalCode
#      90ms  4.07% 40.72%       90ms  4.07%  runtime.scanobject
#      80ms  3.62% 44.34%       80ms  3.62%  syscall.Syscall
#      60ms  2.71% 47.06%       60ms  2.71%  runtime.futex
#      40ms  1.81% 48.87%       40ms  1.81%  encoding/json.(*encodeState).string
#      40ms  1.81% 50.68%       40ms  1.81%  io.ReadAtLeast
