package main

import (
	_ "bufio"
	"fmt"
	"net"
	"os"
	"time"
)

func canaryGo(host string, port string) {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		//	p := make([]byte, 2048)
		fmt.Fprintf(conn, "P%dD", os.Getpid())
		//	_, err = bufio.NewReader(conn).Read(p)
		time.Sleep(time.Second)
	}
}
