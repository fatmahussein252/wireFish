wireFish is a simple packet sniffer program in C++ using the Packet Capture library. It is designed to apply OOP concepts in cpp.

## Features 
- Digest IP and ICMP packets and show their fields.
- Digest the following TCP layer protocols (TCP, UDP).
- Digest the following application layer protocols (HTTP, DNS).
- Support filtering on specific IP/port for source or distination or both using a command line option.

## How to use 
1) compile the program:
```
g++ wireFish.cpp layers.cpp -lpcap
```
2) Run it as sudo user
```
sudo ./a.out
```
To filter on specific ip/port
```
sudo ./a.out srcip <ip> destip <ip> srcport <port> destport <port> # can use any of them individually
``` 
## outputs
![image](https://github.com/user-attachments/assets/e8115e66-9868-45fd-9719-b5e38d0f0398)

![image](https://github.com/user-attachments/assets/4763a106-1552-4ccc-9861-c5c960f50e78)



