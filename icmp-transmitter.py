import time
from scapy.all import *

ip = IP()
icmp = ICMP()

ip.dst = "www.google.com"

count = 0

while True:
	send(ip/icmp, verbose=0)
	count = count + 1
	time.sleep(1)
