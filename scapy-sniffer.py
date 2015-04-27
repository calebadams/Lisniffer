import Tkinter as tk
import ttk
import datetime
import time
import threading
import os
import tkMessageBox
from scapy.all import *

class Main_Gui:
    def __init__(self, master):
        self.master = master
        
        # Create an empty list of threads and initialize the main gui window
        self.threads = []
        self.init_gui()
        
    def init_gui(self):
        self.master.title("Lisniffer") # Set the title of the app
        self.image = tk.PhotoImage(file = "pure-acid.gif") # Create our background image
                
        # Calls all pending idle tasks, without processing any other events
        self.master.update_idletasks()
        
        # Store the height and widths of the window
        self.windowWidth = self.image.width()
        self.windowHeight = self.image.height()
        
        # Set the x and y position of the window
        xPos = (self.master.winfo_screenwidth() / 2) - ((self.windowWidth + 4) / 2)
        yPos = (self.master.winfo_screenheight() / 2) - ((self.windowHeight + 4) / 2)
        
        # Set the geometry of the window to center it in the middle of the screen
        self.master.geometry('{}x{}+{}+{}'.format((self.windowWidth + 4), (self.windowHeight + 4), xPos, yPos))
        
        # Set the frame to the same size
        self.frame = tk.Frame(self.master, width = self.windowWidth, height = self.windowHeight)
        self.frame.grid(row = 0, column = 0, rowspan = 3, columnspan = 3)
        
        # Create our background, must use label widget to do so in Tkinter
        self.backgroundLabel = tk.Label(self.frame, image = self.image)
        self.backgroundLabel.grid(column = 0, row = 0, columnspan = 3, rowspan = 4)
    
        # Create a label to indicate capture time
        self.label = tk.Label(self.frame, text = "Capture Time:", font = ("Helvetica", 18))
        self.label.grid(row = 0, column = 0)
        
        # Create a spinbox that takes anywhere from 1 to 60 seconds
        self.spinBox = tk.Spinbox(self.frame, from_ = 1, to = 60)
        self.spinBox.grid(row = 0, column = 1)
        
        # Create a label for seconds
        self.label = tk.Label(self.frame, text = "sec", font = ("Helvetica", 18))
        self.label.grid(row = 0, column = 2, sticky = tk.W)
        
        # Create a start button to begin sniff/capture
        self.startButton = tk.Button(self.frame, text = "Start", command = self.new_window, width = 50)
        self.startButton.grid(row = 1, column = 0, columnspan = 3)
        
        # Create print button to print to the default printer
        self.printButton = tk.Button(self.frame, text = 'Print', width = 50, command = self.print_file)
        self.printButton.grid(row = 2, column = 0, columnspan = 3)
        
    def print_file(self):
        # Create a new thread to print packets.txt, which is written to during
        # the sniff in the Packet_Sniffer
        printThread = threading.Thread(target = os.system("lpr packets.txt"))
        self.threads.append(printThread) # Append to our list of threads
        printThread.start() # Start the thread
        
        
    def new_window(self):
        # Create a new window using Toplevel (Tkinter practices)        
        self.newWindow = tk.Toplevel(self.master)
        
        self.packet_sniffer_app = Packet_Sniffer(self.newWindow) # Create a new packet sniffer object
        
        # Start second thread for sniff
        sniffThread = threading.Thread(target = sniffer, args = (self.spinBox.get(),self.packet_sniffer_app))
        self.threads.append(sniffThread)
        sniffThread.start()
        
class Packet_Sniffer:
    def __init__(self, master):
        self.master = master

        # Initialize the packet count to 0 and initialize the boolean to false
        self.packetCount = 0
        self.bool_update = False
        
        # Calls check_bool after 10 milliseconds, and will check every 10 milliseconds
        # thereafter
        self.master.after(10, self.check_bool)
        self.outputFile = open('packets.txt', 'w') # Open the packets output file that can be printed later
        
        # Initialize GUI and set the grid of the frame to get it to show up in our new window
        self.init_gui()
        
    def init_gui(self):
        self.frame = tk.Frame(self.master) # Init the frame
        self.frame.grid(row = 0, column = 0, rowspan = 2)
            
        # Create a close button to close the window
        self.closeButton = tk.Button(self.frame, text = 'Close', width = 25, command = self.close_window)
        self.closeButton.grid(row = 1, column = 0)
        
        # Create our IP ttk treeview
        self.ipTree = ttk.Treeview(self.frame, height = 25)
        
        # Setup the column and heading characteristics
        self.ipTree.column("#0",  minwidth = 450, width = 495, stretch = tk.NO)
        self.ipTree.heading("#0", text = "Packets")
        
        # Reset the packet count
        self.packetCount = 0
        
        # Configure the various protocols to display different colors in treeview
        self.ipTree.tag_configure('TCP', background = 'green')
        self.ipTree.tag_configure('UDP', background = "yellow")
        self.ipTree.tag_configure('ICMP', background = "cyan")
        
        # Set the ip treeview to appear in the first row and first column
        self.ipTree.grid(row = 0, column = 0)
    
        # Calls all pending idle tasks, without processing any other events
        self.master.update_idletasks()
        
        # Store the height and widths of the window
        self.windowWidth = self.master.winfo_width()
        self.windowHeight = self.master.winfo_height()
        
        # Set the x and y position of the window
        xPos = (self.master.winfo_screenwidth() / 2) -  (self.windowWidth / 2)
        yPos = (self.master.winfo_screenheight() / 2) - (self.windowHeight / 2)
        
        # Set the geometry of the window to center it in the middle of the screen
        self.master.geometry('{}x{}+{}+{}'.format((self.windowWidth), (self.windowHeight), xPos, yPos))
        
    def print_tree_node(self, pkt):  
        # Parse the packet      
        if IP in pkt: # If its an IP packet, begin processing
            
            # Store the source and destinatin IP addresses
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            
            # Store the time and length of the packet
            ip_time = datetime.datetime.fromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
            ip_len = pkt[IP].len
            
            if TCP in pkt: # If its a TCP packet
                self.packetCount = self.packetCount + 1 # Increment the packet counter
                
                # Store the various elements of the packet
                tcp_sport = pkt[TCP].sport
                tcp_dport = pkt[TCP].dport
                tcp_checksum = hex(pkt[TCP].chksum)
                tcp_seq = str(pkt[TCP].seq)
                tcp_ack = str(pkt[TCP].ack)
                tcp_dataofs = str(pkt[TCP].dataofs)
                tcp_reserved = str(pkt[TCP].reserved)
                tcp_flags = hex(pkt[TCP].flags)
                tcp_window = str(pkt[TCP].window)
                tcp_urgptr = str(pkt[TCP].urgptr)
                
                # Insert the parent treeview element indicating packet number, protocol, src and dst IP
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text = "Packet #" + str(self.packetCount) + 
                                        ": TCP " + str(ip_src) + " to " + str(ip_dst), tags = ("TCP"))
                
                # Insert packet data into the treeview parent ID
                self.ipTree.insert(id, 'end', text = "Src IP:\t\t" + str(ip_src))
                self.ipTree.insert(id, 'end', text = "Scr Port:\t\t" + str(tcp_sport))
                self.ipTree.insert(id, 'end', text = "Dst IP:\t\t" + str(ip_dst))
                self.ipTree.insert(id, 'end', text = "Dst Port:\t\t" + str(tcp_dport))
                self.ipTree.insert(id, 'end', text = "Length:\t\t" + str(ip_len))
                self.ipTree.insert(id, 'end', text = "Time:\t\t" + ip_time)
                self.ipTree.insert(id, 'end', text = "Seq:\t\t" + tcp_seq)
                self.ipTree.insert(id, 'end', text = "Ack:\t\t" + tcp_ack)
                self.ipTree.insert(id, 'end', text = "Offset:\t\t" + tcp_dataofs)
                self.ipTree.insert(id, 'end', text = "Reserved:\t\t" + tcp_reserved)
                self.ipTree.insert(id, 'end', text = "Flags:\t\t" + tcp_flags)
                self.ipTree.insert(id, 'end', text = "Window:\t\t" + tcp_window)
                self.ipTree.insert(id, 'end', text = "Checksum:\t" + tcp_checksum)
                self.ipTree.insert(id, 'end', text = "Urgptr:\t\t" + tcp_urgptr)
                
                # Print the packet data to the output file 
                print >> self.outputFile, "Packet #" + str(self.packetCount)
                print >> self.outputFile, "Proto:\t\tTCP"
                print >> self.outputFile, "Src IP:\t\t" + str(ip_src)
                print >> self.outputFile, "Scr Port:\t" + str(tcp_sport)
                print >> self.outputFile, "Dst IP:\t\t" + str(ip_dst)
                print >> self.outputFile, "Dst Port:\t" + str(tcp_dport)
                print >> self.outputFile, "Length:\t\t" + str(ip_len)
                print >> self.outputFile, "Time:\t\t" + ip_time
                print >> self.outputFile, "Seq:\t\t" + tcp_seq
                print >> self.outputFile, "Ack:\t\t" + tcp_ack
                print >> self.outputFile, "Offset:\t\t" + tcp_dataofs
                print >> self.outputFile, "Reserved:\t" + tcp_reserved
                print >> self.outputFile, "Flags:\t\t" + tcp_flags
                print >> self.outputFile, "Window:\t\t" + tcp_window
                print >> self.outputFile, "Checksum:\t" + tcp_checksum
                print >> self.outputFile, "Urgptr:\t\t" + tcp_urgptr + '\n'
                    
            if UDP in pkt:
                self.packetCount = self.packetCount + 1 # Increment the packet counter

                # Store the various elements of the packet
                udp_sport = pkt[UDP].sport
                udp_dport = pkt[UDP].dport
                udp_chksum = hex(pkt[UDP].chksum)
                
                # Insert the parent treeview element indicating packet number, protocol, src and dst IP
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text = "Packet #" + str(self.packetCount) + 
                                        ": UDP " + str(ip_src) + " to " + str(ip_dst), tags = ("UDP"))
                
                # Insert packet data into the treeview parent ID
                self.ipTree.insert(id, 'end', text = "Src IP:\t\t" + str(ip_src))
                self.ipTree.insert(id, 'end', text = "Src Port:\t\t" + str(udp_sport))
                self.ipTree.insert(id, 'end', text = "Dst IP:\t\t" + str(ip_dst))
                self.ipTree.insert(id, 'end', text = "Dst Port:\t\t" + str(udp_dport))
                self.ipTree.insert(id, 'end', text = "Checksum:\t" + udp_chksum)
                self.ipTree.insert(id, 'end', text = "Length:\t\t" + str(ip_len))
                self.ipTree.insert(id, 'end', text = "Time:\t\t" + str(ip_time))
                
                # Print the packet data to the output file 
                print >> self.outputFile, "Packet #" + str(self.packetCount)
                print >> self.outputFile, "Proto:\t\tUDP"
                print >> self.outputFile, "Src IP:\t\t" + str(ip_src)
                print >> self.outputFile, "Scr Port:\t" + str(udp_sport)
                print >> self.outputFile, "Dst IP:\t\t" + str(ip_dst)
                print >> self.outputFile, "Dst Port:\t" + str(udp_dport)
                print >> self.outputFile, "Checksum:\t" + udp_chksum
                print >> self.outputFile, "Length:\t\t" + str(ip_len)
                print >> self.outputFile, "Time:\t\t" + ip_time + '\n'
                
            if ICMP in pkt: # If its an ICMP packet
                self.packetCount = self.packetCount + 1 # Increment the packet counter

                # Store the various elements of the packet
                icmp_code = pkt[ICMP].code # code
                icmp_chksum = hex(pkt[ICMP].chksum) # Checksum
                icmp_seq = str(pkt[ICMP].seq) # seq
                
                # Insert the parent treeview element indicating packet number, protocol, src and dst IP
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text = "Packet #" + str(self.packetCount) + 
                                        ": ICMP " + str(ip_src) + " to " + str(ip_dst), tags = ("ICMP"))
                
                # Insert packet data into the treeview parent ID
                self.ipTree.insert(id, 'end', text = "Src IP:\t\t" + str(ip_src))
                self.ipTree.insert(id, 'end', text = "Dst IP:\t\t" + str(ip_dst))
                self.ipTree.insert(id, 'end', text = "Code:\t\t" + str(icmp_code))  
                self.ipTree.insert(id, 'end', text = "Checksum:\t" + icmp_chksum)
                self.ipTree.insert(id, 'end', text = "Seq:\t\t" + icmp_seq)
                self.ipTree.insert(id, 'end', text = "Length:\t\t" + str(ip_len))
                self.ipTree.insert(id, 'end', text = "Time:\t\t" + str(ip_time))
                
                # Print the packet data to the output file
                print >> self.outputFile, "Packet #" + str(self.packetCount)
                print >> self.outputFile, "Proto:\t\tICMP"
                print >> self.outputFile, "Src IP:\t\t" + str(ip_src)
                print >> self.outputFile, "Dst IP:\t\t" + str(ip_dst)
                print >> self.outputFile, "Code:\t\t" + str(icmp_code)
                print >> self.outputFile, "Checksum:\t" + icmp_chksum
                print >> self.outputFile, "Seq:\t\t" + icmp_seq
                print >> self.outputFile, "Length:\t\t" + str(ip_len)
                print >> self.outputFile, "Time:\t\t" + ip_time + '\n'
        
    def set_bool_update(self, val):
        self.bool_update = val # Set the boolean to the value
    
    def check_bool(self):
        if self.bool_update: # Checks the boolean value
            self.master.update_idletasks() # If it's set sniff is complete, update
        self.master.after(10, self.check_bool) # Recursive call to check again after 10 milliseconds
        
    def close_window(self):
        self.master.destroy() # Close the window
    
    def close_out_file(self):
        self.outputFile.close() # Close the output file
        
def sniffer(capTime, app): # Sniffer thread function
    sniff(prn = lambda x: app.print_tree_node(x), timeout = int(capTime)) # Start sniffing
    app.set_bool_update(True) # Set the update boolean to true
    tkMessageBox.showinfo("Success", "Sniffing complete") # Display message to indicate sniffing is complete
    app.close_out_file() # Close the output file 

def main():
    root = tk.Tk() # Create root Tkinter app
    app = Main_Gui(root) # Create the main gui window
    root.mainloop() # Start the main thread for Tkinter gui

if __name__ == '__main__':
    main()