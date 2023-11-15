import struct
from network_constants import ETHER_TYPE_DICT, IP_PROTO_DICT

"""
Ethernet II Frame
MAC Dest: 6 bytes
MAC Src: 6 bytes
EtherType: 2 bytes
Payload: 46-1500 bytes
Frame CRC: 4 bytes
"""

class EthernetFrame:
	def __init__(self, data):
		dest_mac, src_mac, ethertype, payload = self.unpack_ethernet_frame(data)
		self.DESTINATION = dest_mac
		self.SOURCE = src_mac
		self.ETHER_TYPE = ethertype
		self.PAYLOAD = payload

	def unpack_ethernet_frame(self, data):
		dest_mac, src_mac, ethertype = struct.unpack('! 6s 6s H', data[:14])
		return dest_mac, src_mac, ethertype, data[14:]

	def mac_to_str(self, data):
		octets = []
		for b in data:
			octets.append(format(b, '02x'))
		return "-".join(octets)

	def __str__(self):
		ether = hex(self.ETHER_TYPE)
		trans = "UNKNOW"

		if self.ETHER_TYPE in ETHER_TYPE_DICT:
			trans = ETHER_TYPE_DICT[self.ETHER_TYPE]

		source = self.mac_to_str(self.SOURCE)
		dest = self.mac_to_str(self.DESTINATION)
		length = len(self.PAYLOAD)

		return f"[ Ethernet - {ether} {trans}; Source: {source}; Dest: {dest}; Len: {length} ]"

"""
IPv4 Header Bytes
Version & IHL: 1 byte
 └─ Version: 4 bits
 └─ IHL: 4 bits
DSCP & ECN: 1 byte
 └─ DSCP: 6 bits
 └─ ECN: 2 bits
Total Length: 2 bytes
Identification: 2 bytes
Flags & Offset: 2 bytes
 └─ Flags: 3 bits
 └─ Offset: 13 bits
Time To Live: 1 byte
Protocol: 1 byte
Header Checksum: 2 bytes
Source IP Address: 4 bytes
Destination IP Address: 4 bytes
Options: (IHL-5)*4 bytes (if IHL>5)
Payload: all the rest
"""

class IPV4:
	ID = 0x0800

	def __init__(self, data):
		VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, LEFTOVER = self.unpack_ipv4(data)
		self.VERSION = VER_IHL >> 4
		self.IHL = VER_IHL & 0x0f
		self.LENGTH = LEN
		self.PROTOCOL = PROTO
		self.SOURCE = SOURCE
		self.DESTINATION = DEST
		options_len = 0
		if self.IHL > 5:
			options_len = (self.IHL-5)*4
		self.OPTIONS = LEFTOVER[:options_len]
		self.PAYLOAD = LEFTOVER[options_len:]

	def unpack_ipv4(self, data):
		VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST = struct.unpack("! B B H H H B B H 4s 4s", data[:20])
		return VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, data[20:]

	def ipv4_to_str(self, data):
		octets = []
		for b in data:
			octets.append(format(b, 'd'))
		return ".".join(octets)
	def __str__(self):
		proto = hex(self.PROTOCOL)
		trans = "UNKNOW"

		if self.PROTOCOL in IP_PROTO_DICT:
			trans = IP_PROTO_DICT[self.PROTOCOL]

		source = self.ipv4_to_str(self.SOURCE)
		dest = self.ipv4_to_str(self.DESTINATION)

		return f"[ IPV4 Proto: {proto} {trans}; Source: {source}; Dest: {dest} ]"

"""
UDP Datagram Header
Source Port: 2 bytes
Destination Port: 2 bytes
Length: 2 bytes
Checksum: 2 bytes
Payload: (Length-8) bytes
"""

class UDP:
	ID = 0x11

	def __init__(self, data):
		SOURCE, DEST, LEN, CHECKSUM, LEFTOVER = self.unpack_udp(data)
		self.SOURCE_PORT = SOURCE
		self.DEST_PORT = DEST
		self.LENGTH = LEN
		self.CHECKSUM = CHECKSUM
		self.PAYLOAD = LEFTOVER

	def unpack_udp(self, data):
		SOURCE, DEST, LEN, CHECKSUM = struct.unpack("! H H H H", data[:8])
		return SOURCE, DEST, LEN, CHECKSUM, data[8:]

	def __str__(self):
		return f"[ UDP - Source Port: {self.SOURCE_PORT}; Destination Port: {self.DEST_PORT}; LEN: {self.LENGTH} ]"

"""
TCP Segment Header
Source Port: 2 bytes
Destination Port: 2 bytes
Sequence number: 4 bytes
Acknowledgment number: 4 bytes (if ACK set)
Data Offset & Flags: 2 bytes
 └─ Data Offset: 4 bits
 └─ Reserved: 3 bits
 └─ NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN: 1 bit for each
Window Size: 2 bytes
Checksum: 2 bytes
Urgent pointer: 2 bytes (if URG set)
Options: (Data Offset-5)*4 bytes (if Data Offset>5)
Payload: all the rest
"""

class TCP:
	ID = 0x06

	def __init__(self, data):
		SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, CHECKSUM, URG_PTR, LEFTOVER = self.unpack_tcp(data)
		self.SOURCE_PORT = SRC
		self.DEST_PORT = DEST
		self.SEQUENCE_NUM = SEQ
		self.ACK_NUM = ACK_NUM
		self.FLAGS = {
			"FIN" : bool(OFFSET_FLAGS & 0x01),
			"SYN" : bool((OFFSET_FLAGS >> 1) & 0x01),
			"RST" : bool((OFFSET_FLAGS >> 2) & 0x01),
			"PSH" : bool((OFFSET_FLAGS >> 3) & 0x01),
			"ACK" : bool((OFFSET_FLAGS >> 4) & 0x01),
			"URG" : bool((OFFSET_FLAGS >> 5) & 0x01),
			"ECE" : bool((OFFSET_FLAGS >> 6) & 0x01),
			"CWR" : bool((OFFSET_FLAGS >> 7) & 0x01),
			"NS" : bool((OFFSET_FLAGS >> 8) & 0x01)
		}
		self.OFFSET = OFFSET_FLAGS >> 12
		self.WINDOW_SIZE = WIN_SIZE
		self.CHECKSUM = CHECKSUM
		self.URGENT_POINTER = URG_PTR

		options_len = 0
		if self.OFFSET > 5:
			options_len = (self.OFFSET-5)*4
		self.PARAMS = LEFTOVER[:options_len]
		self.PAYLOAD = LEFTOVER[options_len:]

	def unpack_tcp(self, data):
		SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, CHECKSUM, URG_PTR = struct.unpack("! H H I I H H H H", data[:20])
		return SRC, DEST, SEQ, ACK_NUM, OFFSET_FLAGS, WIN_SIZE, CHECKSUM, URG_PTR, data[20:]

	def __str__(self):
		active_flags = []
		for key in self.FLAGS:
			if self.FLAGS[key]:
				active_flags.append(key)
		flags_str = ", ".join(active_flags)
		res = "[ TCP - "
		res += f"Source Port: {self.SOURCE_PORT}; "
		res += f"Destination Port: {self.DEST_PORT}; "
		res += f"Flags: ({flags_str}); "
		res += f"Sequence: {self.SEQUENCE_NUM}; "
		res += f"ACK_NUM: {self.ACK_NUM} "
		res += "]"
		return res

def hexdump(bytes_input, left_padding=0, byte_width=16):
	current = 0
	end = len(bytes_input)
	result = ""
	while current < end:
		byte_slice = bytes_input[current : current+byte_width]
		result += " "*left_padding
		for b in byte_slice:
			result += "%02X " % b
		for _ in range(byte_width-len(byte_slice)):
			result += " "*3
		result += "  "

		for b in byte_slice:
			if (b >= 32) and (b < 127):
				result += chr(b)
			else:
				result += "."
		result += "\n"
		current += byte_width
	return result
