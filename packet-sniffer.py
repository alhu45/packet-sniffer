import socket
from scapy.all import *
from scapy.layers.l2 import Ether

sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

interface = "eth0"
sniffer_socket.bind((interface, 0))

try:
    while True:
        raw_data, addr = sniffer_socket.recvfrom(65535)
        packet = Ether(raw_data)
        print(packet.summary())
except KeyboardInterrupt:
    sniffer_socket.close()

"""""
1. Import the necessary modules:
socket: This module is used for creating a raw socket for packet capture.

scapy.all: This module is from the Scapy library, which is a powerful packet manipulation and network scanning tool in Python.

scapy.layers.12: This import is not necessary in this code as it's not being used.

2. Create a raw socket for packet capture:
sniffer_socket is created using the socket.socket constructor with AF_PACKET as the address family, SOCK_RAW as the socket type, and ntohs(3) to specify the protocol to capture (Ethernet frames).

3. Bind the socket to a specific network interface:
The bind method is used to associate the socket with a specific network interface (eth0 in this case) and port (0).

4. Start a packet capture loop:
The script enters an infinite loop (while True) to continuously capture packets.

5. Capture packets:
sniffer_socket.recvfrom(65535) captures raw packet data, where 65535 is the maximum packet size to capture.

The captured raw data is then converted into a Scapy packet object using packet = Ether(raw_data).

6. Print a summary of each captured packet:
packet.summary() is used to print a concise summary of the packet's content.

7. Handle a KeyboardInterrupt:
If the user presses Ctrl+C, the script catches the KeyboardInterrupt exception and closes the sniffer_socket before exiting.
"""