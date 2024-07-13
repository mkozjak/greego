package config

import (
	"flag"
	"log"
)

var (
	port            int
	clientAddress   string
	socketInterface string
	id              string
	key             string
	broadcast       string
)

type App struct {
	Port    int
	Verbose bool
}

type Client struct {
	Key   string
	IP    string
	ID    string
	Bcast string
}

type Config struct {
	App    App
	Client Client
}

func New() *Config {
	flag.IntVar(&port, "port", 4242, "Server listening port")
	flag.StringVar(&clientAddress, "client-address", "", "IP address of the client device")
	flag.StringVar(&socketInterface, "socket-interface", "", "Bind the socket to a specific network interface")
	flag.StringVar(&id, "id", "", "Unique ID of the device")
	flag.StringVar(&key, "key", "", "Unique encryption key of the device")
	flag.StringVar(&broadcast, "broadcast", "", "Broadcast IP address of the network the devices connecting to")
	flag.Parse()

	if clientAddress == "" || socketInterface == "" || id == "" || key == "" || broadcast == "" {
		log.Fatal("Missing mandatory arguments. Use -client-address, -socket-interface, -id, -key and -broadcast flags")
	}

	return &Config{
		App: App{
			Port:    port,
			Verbose: true,
		},
		Client: Client{
			Key:   key,
			IP:    clientAddress,
			ID:    id,
			Bcast: broadcast,
		},
	}
}
