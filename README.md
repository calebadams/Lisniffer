# Lisniffer
Lisniffer is a multithreaded packet sniffer written and tested with Python 2.7.6. The application detects and parses IP, TCP, UDP, and ICMP network protocols. 

# Using Lisniffer

1. The user must specify an amount of time to capture packets (1 to 60 seconds)
2. Click "Start"
3. Wait until a message dialog pops up indicating that sniffing is complete
4. Navigate through and analyze the captured packets
5. If the machine is connected to a default printer ($ lpstat -d) the main GUI "Print" button can be used to print the contents of a generated output file called packets.txt

# To start the app

Enter the following command in the proper working directory of the source files:

$ sudo chmod +x start.sh

$ sudo ./start.sh

# To stop the app
Enter the following command in the same terminal

$ sudo chmod +x stop.sh

$ sudo ./stop.sh

# To Install scapy (Linux):
Run the following commands

$ cd /tmp

$ wget scapy.net

$ unzip scapy-latest.zip

$ cd scapy-2.*

$ sudo python setup.py install

# wget
If the wget command line tool does not download the scapy zip properly, simply visit scapy.net in your web browser to download it and run the rest of the commands from terminal.

Link: http://coolestguidesontheplanet.com/install-and-configure-wget-on-os-x/

# Linux Scapy Installation:
http://www.secdev.org/projects/scapy/doc/installation.html#latest-release

# Mac OS X Scapy Installation:
http://juhalaaksonen.com/blog/2013/12/11/installing-scapy-for-mac-os-x/

Router: It hurts when IP.
