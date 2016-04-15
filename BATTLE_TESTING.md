# Battle Testing

Here are some tests that can be run to see how things perform under weird or heavy conditions

### Receive buffer

The idea of this test is to see where your system will begin having trouble receiving messages from `kauditd`.
It may be possible to tweak the netlink socket receive buffer and avoid this problem. We have not seen any message
loss as a result of this scenario to date.

- Make a file that a user can't read

    `sudo touch /tmp/nope && sudo chmod 0600 /tmp/nope`
    
- Set your `go-audit.yaml` to the following:

    ```
    rules:
      - -a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -k access
      - -a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -k access
    ```
    
- Spawn a bunch of background processes that can't read the file (run the following line many times)

    `while [ true ]; do cat /tmp/nope > /dev/null 2>&1; done &`
    
- Run go audit and observe, it may take a while but you should eventually see the following message

    ```
    Error during message receive: no buffer space available
    ```
    
- Experiment with the `socket_buffer.receive` value in your `go-audit` config.

### Message loss

This tests purpose is to make sure you are recording detected message loss. How quickly message loss is
discovered is currently based on how many audit events occur every second and the value of
`message_tracking.max_out_of_order`

- Set your `go-audit.yaml` to the following:

    ```
    message_tracking:
      enabled: true
      log_out_of_order: false
      max_out_of_order: 2
    rules:
      - -a exit,always -F arch=b64 -S execve
      - -a exit,always -F arch=b32 -S execve
    ```

- Run two instances of `go-audit`. Start one about 2 seconds after the other for best results.

- Spawn a background process that executes a command in a subsecond interval.

    `while [ true ]; do uptime > /dev/null; sleep 0.5; done &`
    
- Observe the output of each process, eventually you should see a log line similar to:

    ```
    Likely missed sequence 100, current 102, worst message delay 0
    ```
