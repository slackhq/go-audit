package main

import (
	_ "bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func canaryGo(host string, port string) {
	for {
		//	p := make([]byte, 2048)
		conn, err := net.Dial("udp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "P%dD", os.Getpid())
		//	_, err = bufio.NewReader(conn).Read(p)
		conn.Close()
		time.Sleep(time.Second)
	}
}
