package main

import (
	"crypto/tls"
	"fmt"
	"os"
)

func main() {
	fmt.Println("TLSCheck")

	if len(os.Args) != 2 {
		fmt.Println("Usage: tlscheck <host:port>")
	} else {
		host := os.Args[1]
		fmt.Println("Checking " + host)

		conf := &tls.Config{}

		conn, err := tls.Dial("tcp", host, conf)
		if err != nil {
			fmt.Println(err)
			return
		}

		defer conn.Close()

		fmt.Println("Connected to " + host)
	}
}
