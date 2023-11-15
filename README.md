# Python Network Sniffer
**Thanks for [@secoats](https://github.com/secoats)'s tutorial and code.**
- Tutorial: https://secoats.github.io/posts/ethernet_sniffer.html
- GitHub repo: https://github.com/secoats/agora_network_sniffer/tree/tutorial

## Example
**Run the sniffer**
```shell
sudo python3 sniffer.py
```
- This sniffer can only parse TCP and UDP packets for now.

**UDP example**
```
[ Ethernet - 0x800 Internet Protocol version 4 (IPv4); Source: 00-00-00-00-00-00; Dest: 00-00-00-00-00-00; Len: 166 ]
└─ [ IPV4 Proto: 0x11 UDP; Source: 127.0.0.53; Dest: 127.0.0.1 ]
   └─ [ UDP - Source Port: 53; Destination Port: 47854; LEN: 146 ]
     66 EA 81 80 00 01 00 03 00 00 00 01 03 77 77 77   f............www
     02 77 33 03 6F 72 67 00 00 1C 00 01 C0 0C 00 05   .w3.org.........
     00 01 00 00 01 29 00 1F 03 77 77 77 02 77 33 03   .....)...www.w3.
     6F 72 67 03 63 64 6E 0A 63 6C 6F 75 64 66 6C 61   org.cdn.cloudfla
     72 65 03 6E 65 74 00 C0 28 00 1C 00 01 00 00 01   re.net..(.......
     29 00 10 26 06 47 00 00 00 00 00 00 00 00 00 68   )..&.G.........h
     12 16 13 C0 28 00 1C 00 01 00 00 01 29 00 10 26   ....(.......)..&
     06 47 00 00 00 00 00 00 00 00 00 68 12 17 13 00   .G.........h....
     00 29 FF D6 00 00 00 00 00 00                     .)........
```
**TCP example**
```
[ Ethernet - 0x800 Internet Protocol version 4 (IPv4); Source: 00-00-00-00-00-00; Dest: 00-00-00-00-00-00; Len: 368 ]
└─ [ IPV4 Proto: 0x6 TCP; Source: 127.0.0.1; Dest: 127.0.0.1 ]
   └─ [ TCP - Source Port: 38965; Destination Port: 43650; Flags: (PSH, ACK); Sequence: 2379334489; ACK_NUM: 1406758873 ]
     48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D   HTTP/1.1 200 OK.
     0A 43 6F 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61   .Content-Type: a
     70 70 6C 69 63 61 74 69 6F 6E 2F 6A 73 6F 6E 3B   pplication/json;
     20 63 68 61 72 73 65 74 3D 75 74 66 2D 38 0D 0A    charset=utf-8..
     56 61 72 79 3A 20 4F 72 69 67 69 6E 0D 0A 44 61   Vary: Origin..Da
     74 65 3A 20 57 65 64 2C 20 31 35 20 4E 6F 76 20   te: Wed, 15 Nov 
     32 30 32 33 20 31 33 3A 30 39 3A 30 39 20 47 4D   2023 13:09:09 GM
     54 0D 0A 43 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74   T..Content-Lengt
     68 3A 20 31 37 38 0D 0A 0D 0A 7B 22 70 6F 72 74   h: 178....{"port
     22 3A 30 2C 22 73 6F 63 6B 73 2D 70 6F 72 74 22   ":0,"socks-port"
     3A 30 2C 22 72 65 64 69 72 2D 70 6F 72 74 22 3A   :0,"redir-port":
     30 2C 22 74 70 72 6F 78 79 2D 70 6F 72 74 22 3A   0,"tproxy-port":
     30 2C 22 6D 69 78 65 64 2D 70 6F 72 74 22 3A 37   0,"mixed-port":7
     38 39 30 2C 22 61 75 74 68 65 6E 74 69 63 61 74   890,"authenticat
     69 6F 6E 22 3A 5B 5D 2C 22 61 6C 6C 6F 77 2D 6C   ion":[],"allow-l
     61 6E 22 3A 74 72 75 65 2C 22 62 69 6E 64 2D 61   an":true,"bind-a
     64 64 72 65 73 73 22 3A 22 2A 22 2C 22 6D 6F 64   ddress":"*","mod
     65 22 3A 22 67 6C 6F 62 61 6C 22 2C 22 6C 6F 67   e":"global","log
     2D 6C 65 76 65 6C 22 3A 22 69 6E 66 6F 22 2C 22   -level":"info","
     69 70 76 36 22 3A 74 72 75 65 7D 0A               ipv6":true}.
```