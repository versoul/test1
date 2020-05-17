package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

var (
	hub        *Hub
	serverAddr string
	deviceName string
)

func serveWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}
	client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
}

func main() {
	flag.StringVar(&deviceName, "device", "", "device name to sniff")
	flag.StringVar(&serverAddr, "addr", "", "server address to listen")
	flag.Parse()

	go sniffDevice(deviceName)

	fmt.Println("Start Server: " + serverAddr)
	fs := http.FileServer(http.Dir("./static/"))
	hub = newHub()
	go hub.run()

	http.Handle("/", fs)
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})
	err := http.ListenAndServe(serverAddr, nil)
	if err != nil {
		panic(err)
	}
}
