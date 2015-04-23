import Tkinter as tk
import ttk
from scapy.all import *
import datetime

class Main_Gui:
    def __init__(self, master):
        self.master = master
        self.init_gui()
        
    def init_gui(self):
        self.image = tk.PhotoImage(file="pure-acid.gif")
        
        self.windowWidth = self.image.width()
        self.windowHeight = self.image.height()
        
        self.frame = tk.Frame(self.master, width=self.windowWidth, height=self.windowHeight)
        self.frame.pack_propagate(0) # set the flag to use the size
        
        self.master.title("Lisniffer")
        self.backgroundLabel = tk.Label(self.frame, image=self.image)
        self.backgroundLabel.place(x=0, y=0, relwidth=1, relheight=1)

        self.label = tk.Label(self.frame, text="Capture Time:", font=("Helvetica", 20))
        self.label.place(x = 140, y = 160)
        
        self.spinBox = tk.Spinbox(self.frame, from_=1, to=60)
        self.spinBox.place(x = 290, y = 160)
        
        self.startButton = tk.Button(self.frame, text = "Start", command = self.new_window, width = 50)
        self.startButton.place(x = 110, y = 190)
        
        self.frame.pack()
        
    def new_window(self):
        Main_Gui.spinBoxVal = self.spinBox.get()
        
        self.newWindow = tk.Toplevel(self.master)
        self.newWindow.geometry("500x500")
        
        self.app = Packet_Sniffer(self.newWindow)

class Packet_Sniffer:
    def __init__(self, master):
        self.master = master
        self.packetCount = 0
        
        self.init_gui() 
        self.frame.pack()
        
    def init_gui(self):
        self.frame = tk.Frame(self.master)
        
        self.spinBoxVal = Main_Gui.spinBoxVal
        
        self.quitButton = tk.Button(self.frame, text = 'Close', width = 25, command = self.close_windows)
        self.quitButton.pack()   
        
        self.ipTree = ttk.Treeview(self.frame, height = 25)
        
        self.ipTree.column("#0",  minwidth = 450, width = 495, stretch=tk.NO)
        self.ipTree.heading("#0", text="Packets")
        
        self.packetCount = 0
        
        sniff(prn=lambda x: self.print_tree_node(x), timeout=int(self.spinBoxVal))
        
        self.ipTree.tag_configure('TCP', background='green')
        self.ipTree.tag_configure('UDP', background='blue')
        self.ipTree.tag_configure('ICMP', background='red')
        
        self.ipTree.pack()
        
    def print_tree_node(self, pkt):
        if IP in pkt:
            
            self.packetCount = self.packetCount + 1
            
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            
            ip_time = datetime.datetime.fromtimestamp(pkt[IP].time).strftime('%Y-%m-%d %H:%M:%S')
            ip_len = pkt[IP].len
            
            if TCP in pkt:
                tcp_sport = pkt[TCP].sport # Source port
                tcp_dport = pkt[TCP].dport # Destination port
                tcp_checksum = hex(pkt[TCP].chksum) # Checksum
                
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text="Packet #" + str(self.packetCount) + 
                                        ": TCP " + str(ip_src) + " to " + str(ip_dst), tags = ("TCP"))
                
                # Insert tree data
                self.ipTree.insert(id, 'end', text="Src IP:\t\t" + str(ip_src))
                self.ipTree.insert(id, 'end', text="Scr Port:\t\t" + str(tcp_sport))
                self.ipTree.insert(id, 'end', text="Dst IP:\t\t" + str(ip_dst))
                self.ipTree.insert(id, 'end', text="Dst Port:\t\t" + str(tcp_dport))
                self.ipTree.insert(id, 'end', text="Checksum:\t" + tcp_checksum)
                self.ipTree.insert(id, 'end', text="Length:\t\t" + str(ip_len))
                self.ipTree.insert(id, 'end', text="Time:\t\t" + ip_time)
                    
            if UDP in pkt:
                udp_sport = pkt[UDP].sport # Source port
                udp_dport = pkt[UDP].dport # Destination port
                udp_chksum = hex(pkt[UDP].chksum) # Checksum
                    
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text="Packet #" + str(self.packetCount) + 
                                        ": UDP " + str(ip_src) + " to " + str(ip_dst), tags = ("UDP"))
                
                # Insert tree data
                self.ipTree.insert(id, 'end', text="Src IP:\t\t" + str(ip_src))
                self.ipTree.insert(id, 'end', text="Src Port:\t\t" + str(udp_sport))
                self.ipTree.insert(id, 'end', text="Dst IP:\t\t" + str(ip_dst))
                self.ipTree.insert(id, 'end', text="Dst Port:\t\t" + str(udp_dport))
                self.ipTree.insert(id, 'end', text="Checksum:\t" + udp_chksum)
                self.ipTree.insert(id, 'end', text="Length:\t\t" + str(ip_len))
                self.ipTree.insert(id, 'end', text="Time:\t\t" + str(ip_time))
                
            if ICMP in pkt:
                icmp_code = pkt[ICMP].code # code
                icmp_id = hex(pkt[ICMP].id) # id
                icmp_chksum = hex(pkt[ICMP].chksum) # Checksum
                icmp_seq = hex(pkt[ICMP].seq) # seq
                
                id = self.ipTree.insert("" , self.packetCount - 1, 
                                        text="Packet #" + str(self.packetCount) + 
                                        ": ICMP ", tags = ("ICMP"))
                
                self.ipTree.insert(id, 'end', text="Code:\t\t" + str(icmp_code))  
                self.ipTree.insert(id, 'end', text="Checksum:\t" + icmp_chksum)
                self.ipTree.insert(id, 'end', text="Id:\t\t" + icmp_id)
                self.ipTree.insert(id, 'end', text="Seq:\t\t" + icmp_seq)
                
        
    def close_windows(self):
        self.master.destroy()

def main(): 
    root = tk.Tk()
    app = Main_Gui(root)
    root.mainloop()

if __name__ == '__main__':
    main()