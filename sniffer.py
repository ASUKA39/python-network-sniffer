import socket
import struct
from ethernet_tools import EthernetFrame, IPV4, UDP, TCP, hexdump
from colors import *

ETH_P_ALL = 0x03
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

while True:
	try:
		raw_data, addr = s.recvfrom(65565)
		frame = EthernetFrame(raw_data)
		print(str(frame))

		if frame.ETHER_TYPE == IPV4.ID:
			ipv4 = IPV4(frame.PAYLOAD)
			print(blue("└─ " + str(ipv4)))
			if ipv4.PROTOCOL == UDP.ID:
				udp = UDP(ipv4.PAYLOAD)
				print(yellow("   └─ " + str(udp)))
				print(yellow(hexdump(udp.PAYLOAD, 5)))
			if ipv4.PROTOCOL == TCP.ID:
				tcp = TCP(ipv4.PAYLOAD)
				print(green("   └─ " + str(tcp)))
				print(green(hexdump(tcp.PAYLOAD, 5)))
	except Exception as e:
		print(red("[ Error: Failed To Parse Frame Data ]"))
		print(red(str(e)))
