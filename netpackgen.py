import threading
import tkinter as tk
import tkinter.font as tkFont

from tkinter import messagebox
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, send

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import os
import random
import time
import base64

try:
    from Crypto import Random
except ImportError:
    messagebox.showerror("Error", "Crypto module not found. Install it using: pip install pycryptodome")
    sys.exit(1)

# Generate RSA keys
rsa_key = RSA.generate(2048)
private_key = rsa_key.export_key()
public_key = rsa_key.publickey().export_key()

# AES key: generate a random 128-bit key
aes_key = os.urandom(16)

# Global flag to control continuous sending
sending_packets = False
# Global counter for sent packets
packet_count = 0

def encrypt_payload(payload):
    """Encrypt the payload using AES and then encrypt the AES key with RSA."""
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    encrypted_payload = aes_cipher.encrypt(pad(payload.encode(), AES.block_size))
    
    rsa_cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    
    return base64.b64encode(encrypted_aes_key + encrypted_payload).decode()

def validate_form():
    if len(src_mac_entry.get()) == 0:
        messagebox.showerror("Error", "Source MAC address is empty. Please type a value.")
        return False
    if len(dst_mac_entry.get()) == 0:
        messagebox.showerror("Error", "Destination MAC address is empty. Please type a value.")
        return False
    if len(src_ip_entry.get()) == 0:
        messagebox.showerror("Error", "Source IP address is empty. Please type a value.")
        return False
            
    protocol = protocol_var.get()
    
    if protocol != "ARP":
        if len(dst_ip_entry.get()) == 0:
            messagebox.showerror("Error", "Destination IP address is empty. Please type a value.")
            return False
        if len(ip_id_entry.get()) == 0:
            messagebox.showerror("Error", "IP ID is empty. Please type a value.")
            return False
        if len(tos_entry.get()) == 0:
            messagebox.showerror("Error", "TOS is empty. Please type a value.")
            return False
        
    # validate fields for TCP
    if protocol == "TCP":
        if len(dst_port_entry.get()) == 0:
            messagebox.showerror("Error", "Destination Port is empty. Please type a value.")
            return False
        if len(tcp_flags_var.get()) == 0:
            messagebox.showerror("Error", "TCP flag is empty. Please select a value from the list.")
            return False
        if len(ttl_entry.get()) == 0:
            messagebox.showerror("Error", "TTL is empty. Please select a value from the list.")
            return False
     
    # validate fields for UCP
    if protocol == "UDP":
        if len(dst_port_entry.get()) == 0:
            messagebox.showerror("Error", "Destination Port is empty. Please type a value.")
            return False
        
    # validate fields for ICMP
    if protocol == "ICMP":
        if len(icmp_type_entry.get()) == 0:
            messagebox.showerror("Error", "TCP flag is empty. Please select a value from the list.")
            return False

    return True

def send_packet():
    """Send a packet based on user input with custom headers."""
    global packet_count

    if not validate_form():
        return

    # read values from the form
    protocol = protocol_var.get()
    src_mac = src_mac_entry.get()
    dst_mac = dst_mac_entry.get()
    src_ip = src_ip_entry.get()
    dst_ip = dst_ip_entry.get()
    dst_port = dst_port_entry.get()
    payload = payload_entry.get()
    ttl = ttl_entry.get()
    tos = tos_entry.get()
    ip_id = ip_id_entry.get()
    tcp_flags = tcp_flags_var.get()
    icmp_type = icmp_type_entry.get()

    if encrypt_var.get():
        payload = encrypt_payload(payload)

    ether_layer = Ether(src=src_mac, dst=dst_mac)

    if protocol != "ARP":
        ip_layer = IP(src=src_ip, dst=dst_ip, ttl=int(ttl), tos=int(tos), id=int(ip_id))
    
    if protocol == "TCP":
        packet = ether_layer / ip_layer / TCP(dport=int(dst_port), flags=tcp_flags) / payload
    elif protocol == "UDP":
        packet = ether_layer / ip_layer / UDP(dport=int(dst_port)) / payload
    elif protocol == "ICMP":
        packet = ether_layer / ip_layer / ICMP(type=int(icmp_type)) / payload
    elif protocol == "ARP":
        packet = ether_layer / ARP(pdst=dst_ip)
    else:
        messagebox.showerror("Error", "Invalid Protocol Selected")
        return
    
    send(packet, verbose=False)
    packet_count += 1
    packet_count_label.config(text=f"Packets Sent: {packet_count}")

def send_one():
    global packet_count
    packet_count = 0
    packet_count_label.config(text=f"Packets Sent: {packet_count}")

    sending_packets = False
    send_packet()

def send_continuous():
    """Send packets continuously until stopped."""
    global sending_packets
    while sending_packets:
        send_packet()
        time.sleep(1)

def toggle_sending():
    """Toggle packet sending on or off."""
    global packet_count
    global sending_packets

    if not sending_packets:
        if not validate_form():
            return
        
        packet_count = 0
        packet_count_label.config(text=f"Packets Sent: {packet_count}")

        sending_packets = True
        send_button.config(text="Stop Sending")
        threading.Thread(target=send_continuous, daemon=True).start()
    else:
        sending_packets = False
        send_button.config(text="Start Sending")

def update_fields(*args):
    """Enable or disable fields based on selected protocol."""
    protocol = protocol_var.get()
    if protocol == "TCP":
        dst_port_entry.config(state="normal")
        tcp_flags_menu.config(state="normal")
        icmp_type_entry.config(state="disabled")
        ttl_entry.config(state="normal")
        tos_entry.config(state="normal")
    elif protocol == "UDP":
        dst_port_entry.config(state="normal")
        tcp_flags_menu.config(state="disabled")
        icmp_type_entry.config(state="disabled")
        ttl_entry.config(state="normal")
        tos_entry.config(state="normal")
    elif protocol == "ICMP":
        dst_port_entry.config(state="disabled")
        tcp_flags_menu.config(state="disabled")
        icmp_type_entry.config(state="normal")
        ttl_entry.config(state="normal")
        tos_entry.config(state="normal")
    elif protocol == "ARP":
        dst_port_entry.config(state="disabled")
        tcp_flags_menu.config(state="disabled")
        ttl_entry.config(state="disabled")
        tos_entry.config(state="disabled")
        icmp_type_entry.config(state="disabled")

def load_defaults():
    """Load default values into the input fields."""
    src_mac_entry.insert(0, "00:11:22:33:44:55")
    dst_mac_entry.insert(0, "66:77:88:99:AA:BB")
    src_ip_entry.insert(0, "192.168.1.1")
    dst_ip_entry.insert(0, "192.168.1.2")
    dst_port_entry.insert(0, "80")
    ttl_entry.insert(0, "64")
    tos_entry.insert(0, "0")
    ip_id_entry.insert(0, "1")
    tcp_flags_var.set("S")
    icmp_type_entry.insert(0, "8")
    payload_entry.insert(0, "Hello World!")

# GUI Setup
root = tk.Tk()
root.title("Network Packet Generator")
root.geometry("700x500")  # Adjusted window size

pixelVirtual = tk.PhotoImage(width=1, height=1)
ButtonFontStyle = tkFont.Font(family="Lucida Grande", size=12)
EntryFontStyle = tkFont.Font(family="Lucida Grande", size=14)
LabelFontStyle = tkFont.Font(family="Lucida Grande", size=12)
MenuFontStyle = tkFont.Font(family="Lucida Grande", size=12)

# Protocol Selection
tk.Label(root, text="Protocol:", 
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=0, column=0, padx=10)
protocol_var = tk.StringVar(value="TCP")
protocol_var.trace_add("write", update_fields)
protMenu = tk.OptionMenu(root, protocol_var, "ARP", "TCP", "UDP", "ICMP")
protMenu.config(font=MenuFontStyle, width=20)
protMenu.grid(row=0, column=1, padx=10, pady=5)

# Entry fields
tk.Label(root, text="Source MAC:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=1, column=0)
src_mac_entry = tk.Entry(root, font=EntryFontStyle)
src_mac_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(root, 
         text="Destination MAC:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=2, column=0)
dst_mac_entry = tk.Entry(root, font=EntryFontStyle)
dst_mac_entry.grid(row=2, column=1, padx=10, pady=5)

tk.Label(root, text="Source IP:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=3, column=0)
src_ip_entry = tk.Entry(root, font=EntryFontStyle)
src_ip_entry.grid(row=3, column=1, padx=10, pady=5)

tk.Label(root, text="Destination IP:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=4, column=0)
dst_ip_entry = tk.Entry(root, font=EntryFontStyle)
dst_ip_entry.grid(row=4, column=1, padx=10, pady=5)

tk.Label(root, text="Destination Port:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=5, column=0)
dst_port_entry = tk.Entry(root, font=EntryFontStyle)
dst_port_entry.grid(row=5, column=1, padx=10, pady=5)

tk.Label(root, text="TTL:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=6, column=0)
ttl_entry = tk.Entry(root, font=EntryFontStyle)
ttl_entry.grid(row=6, column=1, padx=10, pady=5)

tk.Label(root, text="TOS:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=7, column=0)
tos_entry = tk.Entry(root, font=EntryFontStyle)
tos_entry.grid(row=7, column=1, padx=10, pady=5)

tk.Label(root, text="IP ID:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=8, column=0)
ip_id_entry = tk.Entry(root, font=EntryFontStyle)
ip_id_entry.grid(row=8, column=1, padx=10, pady=5)

tk.Label(root, text="TCP Flags:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=9, column=0)
tcp_flags_var = tk.StringVar(value="S")
tcp_flags_menu = tk.OptionMenu(root, tcp_flags_var, "S", "A", "F", "R", "P", "U")
tcp_flags_menu.config(font=MenuFontStyle, width=20)
tcp_flags_menu.grid(row=9, column=1, padx=10, pady=5)

tk.Label(root, text="ICMP Type:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=10, column=0)
icmp_type_entry = tk.Entry(root, font=EntryFontStyle)
icmp_type_entry.grid(row=10, column=1, padx=10, pady=5)

tk.Label(root, text="Payload:",
         font=LabelFontStyle,
         anchor="w",
         justify="left",
         width=20).grid(row=11, column=0)
payload_entry = tk.Entry(root, font=EntryFontStyle)
payload_entry.grid(row=11, column=1, padx=10, pady=5)

# Encryption Checkbox
encrypt_var = tk.BooleanVar(value=False)
encrypt_checkbox = tk.Checkbutton(root, text="Encrypt Payload", variable=encrypt_var, font=LabelFontStyle)
encrypt_checkbox.grid(row=12, column=1)

packet_count_label = tk.Label(root, 
                              text="Packets Sent: 0",
                              anchor="w",
                              justify="center",
                              width=30)
packet_count_label.grid(row=6, column=2, padx=15, pady=15)

# Buttons
tk.Button(root, 
          text="Load Default Values", 
          image=pixelVirtual,
          command=load_defaults, 
          font=ButtonFontStyle,
          width=175, 
          compound="c").grid(row=1, column=2, padx=10, pady=5)

send_one_button = tk.Button(root, 
                            text="Send One Packet", 
                            command=send_one,
                            image=pixelVirtual,
                            font=ButtonFontStyle,
                            width=175, 
                            compound="c")
send_one_button.grid(row=3, column=2)

send_button = tk.Button(root, 
                        text="Start Sending", 
                        command=toggle_sending, 
                        image=pixelVirtual,
                        font=ButtonFontStyle,
                        width=175, 
                        compound="c")
send_button.grid(row=4, column=2)

icmp_type_entry.config(state="disabled")

# Initialize field states
update_fields()

try:
    from ctypes import windll
    windll.shcore.SetProcessDpiAwareness(1)
except:
    messagebox.showwarning("Warning", "Maybe you find the text and UI are blurry on Windows")
finally:
    root.mainloop()
