package main

import (
	"fmt"
	"io"
	"net"
	"log"
)

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:9996")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Println("Echo server listening on 127.0.0.1:9996")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New connection from %s\n", conn.RemoteAddr())

	// Echo back everything
	io.Copy(conn, conn)
}
