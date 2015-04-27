import time
from scapy.all import *

ip = IP()
ip.show()

icmp = ICMP()
icmp.show()

ip.dst = "192.168.0.1"

count = 0

while True:
	send(ip/icmp)
	count = count + 1
	time.sleep(1)
	print "Sent packet #" + str(count)
