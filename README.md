#### SSL handshake sniffer

This is simple solution to the problem described [here](TASK.md)

Instal depedencies

```sudo apt-get install libpcap-dev```

Build

```
go get
go build
```

Run 

```
sudo sniffer -device='enp3s0' -addr=':8089'
device = device name to sniff ( you can find by ifconfig command)
addr = where start server

then go to http://localhost:8089
```

