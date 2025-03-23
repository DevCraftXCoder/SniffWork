import socket
import struct
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, ttk
import threading
from scapy.all import sniff, wrpcap, ARP, IP, TCP, UDP, DNS, Raw, ICMP, DNSQR, DNSRR, Ether  # Import necessary protocols from scapy
import time  # Ensure the time module is imported
import json
import tkinter.filedialog  # Import filedialog for directory selection
import matplotlib.pyplot as plt  # Import matplotlib for plotting
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # For embedding plots in Tkinter
import logging
from collections import deque
import os
import subprocess
import platform
import gc
import csv
import re
import sys

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s', filename='packet_sniffer.log', filemode='a')

class PacketSnifferApp:
    def __init__(self, root):
        # Clear terminal on startup
        self.clear_terminal()
        
        # Print welcome banner
        self.print_welcome_banner()
        
        self.root = root
        self.root.title("SniffWork")
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Calculate window size (55% width, 70% height)
        window_width = int(screen_width * 0.55)
        window_height = int(screen_height * 0.70)
        
        # Calculate position for center of screen
        position_x = (screen_width - window_width) // 2
        position_y = (screen_height - window_height) // 2
        
        # Set window size and position
        self.root.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
        
        # Set window icon
        try:
            # Get the directory where the script is located
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, "Angry.ico")
            
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
            else:
                print(f"Warning: Icon file not found at {icon_path}")
        except Exception as e:
            print(f"Warning: Could not load icon file: {str(e)}")
        
        # Initialize variables first
        self.init_variables()
        
        # Create a menu bar
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)

        # Add a "View" menu
        view_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="View", menu=view_menu)

        # Add the Toggle Dark Mode option
        view_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)

        # Initialize additional statistics
        self.total_bytes = 0  # Total bytes captured
        self.packet_sizes = []  # List to store sizes of captured packets

        # Initialize packet count and statistics
        self.packet_count = 0
        self.protocol_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0}
        self.sniffing = False  # Flag to control sniffing
        self.captured_packets = []  # Store captured packets for export
        self.log_file = "packet_log.json"  # Log file for packet details

        # Use lists to store packet data
        self.packet_times = []  # Store all packet times
        self.packet_counts = []  # Store all packet counts
        self.bytes_counts = []  # Store all byte counts
        self.start_time = time.time()

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root, style="TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create tabs
        self.create_tabs()

        # Define styles for light and dark modes
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#FFFFFF")  # Light mode
        self.style.configure("Dark.TFrame", background="#2E2E2E")  # Dark mode
        self.style.configure("TLabel", background="#FFFFFF", foreground="black")  # Light mode labels
        self.style.configure("Dark.TLabel", background="#2E2E2E", foreground="white")  # Dark mode labels
        self.style.configure("TButton", background="#007BFF", foreground="white")  # Button style

        self.is_dark_mode = False  # Track whether dark mode is enabled
        self.is_updating_graph = False  # Initialize the flag

        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Add protocol-specific counters and times
        self.protocol_times = {'TCP': [], 'UDP': [], 'ICMP': [], 'ARP': [], 'DNS': [], 'All': []}
        self.protocol_counts = {'TCP': [], 'UDP': [], 'ICMP': [], 'ARP': [], 'DNS': [], 'All': []}
        self.protocol_current_count = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0, 'All': 0}

    def init_variables(self):
        """Initialize all variables used in the application."""
        # Protocol selection variable
        self.protocol_var = tk.StringVar(value="All")
        
        # Packet counting variables
        self.packet_count = 0
        self.total_bytes = 0
        self.packet_sizes = []
        self.captured_packets = []
        
        # Protocol specific counters
        self.protocol_count = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'DNS': 0
        }
        
        # Sniffing control
        self.sniffing = False
        self.start_time = time.time()
        
        # Time series data
        self.packet_times = []
        self.packet_counts = []
        self.bytes_counts = []
        
        # Protocol-specific data
        self.protocol_times = {
            'TCP': [],
            'UDP': [],
            'ICMP': [],
            'ARP': [],
            'DNS': [],
            'All': []
        }
        self.protocol_counts = {
            'TCP': [],
            'UDP': [],
            'ICMP': [],
            'ARP': [],
            'DNS': [],
            'All': []
        }
        self.protocol_current_count = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'DNS': 0,
            'All': 0
        }
        
        # File handling
        self.log_file = "packet_log.json"
        
        # Dark mode tracking
        self.is_dark_mode = False
        self.is_updating_graph = False

    def create_tabs(self):
        """Create the tabs for the application."""
        self.packet_filter_tab = ttk.Frame(self.notebook)
        self.logging_tab = ttk.Frame(self.notebook)
        self.inspection_tab = ttk.Frame(self.notebook)
        self.statistics_tab = ttk.Frame(self.notebook)

        self.notebook.add(self.packet_filter_tab, text="Packet Filtering")
        self.notebook.add(self.logging_tab, text="Packet Logging")
        self.notebook.add(self.inspection_tab, text="Deep Packet Inspection")
        self.notebook.add(self.statistics_tab, text="Live Statistics")

        # Create frames for different sections
        self.packet_filter_frame = ttk.Frame(self.packet_filter_tab)
        self.packet_filter_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.logging_frame = ttk.Frame(self.logging_tab)
        self.logging_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.inspection_frame = ttk.Frame(self.inspection_tab)
        self.inspection_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.statistics_frame = ttk.Frame(self.statistics_tab)
        self.statistics_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        self.create_packet_filter_tab()
        self.create_logging_tab()
        self.create_inspection_tab()
        self.create_statistics_tab()

        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, event):
        """Handle tab change events."""
        selected_tab = self.notebook.tab(self.notebook.select(), "text")
        logging.info(f"Switched to tab: {selected_tab}")
        # You can add logic here to update the content of the tab if needed

    def create_packet_filter_tab(self):
        """Create the content for the Packet Filtering tab."""
        # Create main container frame
        self.packet_filter_frame = ttk.Frame(self.packet_filter_tab)
        self.packet_filter_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Main output text area with frame for centering
        text_frame = ttk.Frame(self.packet_filter_frame)
        text_frame.pack(expand=True, fill=tk.BOTH)
        
        self.output_text = scrolledtext.ScrolledText(
            text_frame,
            width=80,
            height=25,
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.output_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.output_text.config(state='disabled')  # Make it read-only

        # Control frame for packet count and protocol selection
        control_frame = ttk.Frame(self.packet_filter_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        # Center container for controls
        center_control = ttk.Frame(control_frame)
        center_control.pack(expand=True)

        # Packet count label
        self.packet_count_label = tk.Label(
            center_control,
            text="Packets Captured: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.packet_count_label.pack(side=tk.LEFT, padx=10)

        # Protocol filter dropdown
        self.protocol_var = tk.StringVar(value="All")
        protocol_options = ["All", "TCP", "UDP", "ICMP", "ARP", "DNS"]
        protocol_menu = ttk.OptionMenu(center_control, self.protocol_var, *protocol_options)
        protocol_menu.pack(side=tk.LEFT, padx=10)

        # IP Entry frame
        ip_frame = ttk.Frame(self.packet_filter_frame)
        ip_frame.pack(fill=tk.X, padx=10, pady=5)

        # Center container for IP entry
        center_ip = ttk.Frame(ip_frame)
        center_ip.pack(expand=True)

        self.ip_entry = tk.Entry(center_ip, width=20, font=("Arial", 12))
        self.ip_entry.pack(pady=5)
        self.ip_entry.insert(0, "Enter IP Address")
        self.ip_entry.bind("<FocusIn>", self.on_entry_click)
        self.ip_entry.bind("<FocusOut>", self.on_focus_out)

        # Button frames
        button_frame = ttk.Frame(self.packet_filter_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)

        # Center container for buttons
        center_buttons = ttk.Frame(button_frame)
        center_buttons.pack(expand=True)

        # Blue buttons frame
        blue_button_frame = ttk.Frame(center_buttons)
        blue_button_frame.pack(pady=5)

        # Blue Buttons
        start_button = tk.Button(
            blue_button_frame,
            text="Start Sniffing",
            command=self.start_sniffing_thread,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        start_button.pack(side=tk.LEFT, padx=5)

        ping_button = tk.Button(
            blue_button_frame,
            text="Ping",
            command=self.ping,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        ping_button.pack(side=tk.LEFT, padx=5)

        # Red buttons frame
        red_button_frame = ttk.Frame(center_buttons)
        red_button_frame.pack(pady=5)

        # Red Buttons
        stop_button = tk.Button(
            red_button_frame,
            text="Stop Sniffing",
            command=self.stop_sniffing,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        stop_button.pack(side=tk.LEFT, padx=5)

        clear_button = tk.Button(
            red_button_frame,
            text="Clear Output",
            command=self.clear_output,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        clear_button.pack(side=tk.LEFT, padx=5)

        clear_cache_button = tk.Button(
            red_button_frame,
            text="Clear Cache",
            command=self.clear_cache,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        clear_cache_button.pack(side=tk.LEFT, padx=5)

    def on_entry_click(self, event):
        """Clear placeholder text when entry is clicked."""
        if self.ip_entry.get() == "Enter IP Address":
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.config(fg='black')

    def on_focus_out(self, event):
        """Restore placeholder text if entry is empty."""
        if self.ip_entry.get() == "":
            self.ip_entry.insert(0, "Enter IP Address")
            self.ip_entry.config(fg='grey')

    def create_logging_tab(self):
        """Create the content for the Packet Logging tab."""
        # Create main container frame
        logging_container = ttk.Frame(self.logging_frame)
        logging_container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Text area frame
        text_frame = ttk.Frame(logging_container)
        text_frame.pack(expand=True, fill=tk.BOTH)

        self.logging_text = scrolledtext.ScrolledText(
            text_frame,
            width=80,
            height=25,
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.logging_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.logging_text.config(state='disabled')  # Make it read-only

        # Create a frame for buttons
        button_frame = ttk.Frame(logging_container)
        button_frame.pack(fill=tk.X, pady=5)

        # Center container for buttons
        center_buttons = ttk.Frame(button_frame)
        center_buttons.pack(expand=True)

        # Create left frame for blue buttons
        blue_button_frame = ttk.Frame(center_buttons)
        blue_button_frame.pack(side=tk.LEFT, padx=10)

        # Create right frame for export buttons
        export_button_frame = ttk.Frame(center_buttons)
        export_button_frame.pack(side=tk.LEFT, padx=10)

        # Create frame for red buttons
        red_button_frame = ttk.Frame(center_buttons)
        red_button_frame.pack(side=tk.LEFT, padx=10)

        # Blue buttons (viewing and updating)
        log_button = tk.Button(
            blue_button_frame,
            text="View Packet Log",
            command=self.view_packet_log,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        log_button.pack(side=tk.LEFT, padx=5)

        update_log_button = tk.Button(
            blue_button_frame,
            text="Update View Log",
            command=self.update_view_log,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        update_log_button.pack(side=tk.LEFT, padx=5)

        # Export buttons (green)
        export_json_button = tk.Button(
            export_button_frame,
            text="Export to JSON",
            command=self.export_packet_log,
            bg="#28a745",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        export_json_button.pack(side=tk.LEFT, padx=5)

        export_csv_button = tk.Button(
            export_button_frame,
            text="Export to CSV",
            command=self.export_to_csv,
            bg="#28a745",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        export_csv_button.pack(side=tk.LEFT, padx=5)

        # Clear logs button (red)
        clear_logs_button = tk.Button(
            red_button_frame,
            text="Clear Logs",
            command=self.clear_packet_logs,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        clear_logs_button.pack(side=tk.LEFT, padx=5)

    def clear_packet_logs(self):
        """Clear the packet log file after confirmation."""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all packet logs? This cannot be undone."):
            try:
                # Clear the log file
                open(self.log_file, 'w').close()
                
                # Clear the display
                self.clear_text(self.logging_text)
                self.insert_text(self.logging_text, "Packet logs cleared.\n")
                
                # Reset pagination
                self.current_page = 0
                if hasattr(self, 'page_label'):
                    self.page_label.config(text="Page 1 of 1")
                if hasattr(self, 'prev_button'):
                    self.prev_button.config(state=tk.DISABLED)
                if hasattr(self, 'next_button'):
                    self.next_button.config(state=tk.DISABLED)
                
                messagebox.showinfo("Success", "Packet logs have been cleared successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear packet logs: {str(e)}")
                logging.error(f"Error clearing packet logs: {e}")

    def create_inspection_tab(self):
        """Create the content for the Deep Packet Inspection tab."""
        # Create main container frame
        inspection_container = ttk.Frame(self.inspection_frame)
        inspection_container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Text area frame
        text_frame = ttk.Frame(inspection_container)
        text_frame.pack(expand=True, fill=tk.BOTH)

        self.inspection_text = scrolledtext.ScrolledText(
            text_frame,
            width=80,
            height=25,
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.inspection_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.inspection_text.config(state='disabled')  # Make it read-only

        # Button frame
        button_frame = ttk.Frame(inspection_container)
        button_frame.pack(fill=tk.X, pady=5)

        # Center container for buttons
        center_buttons = ttk.Frame(button_frame)
        center_buttons.pack(expand=True)

        # Analysis buttons frame
        analysis_button_frame = ttk.Frame(center_buttons)
        analysis_button_frame.pack(pady=5)

        # Analyze Last Packet button
        inspect_button = tk.Button(
            analysis_button_frame,
            text="Analyze Last Packet",
            command=self.analyze_last_packet,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        inspect_button.pack(side=tk.LEFT, padx=5)

        # Analyze All Packets button
        analyze_all_button = tk.Button(
            analysis_button_frame,
            text="Analyze All Packets",
            command=self.analyze_all_packets,
            bg="#007BFF",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        analyze_all_button.pack(side=tk.LEFT, padx=5)

        # Clear Analysis button
        clear_analysis_button = tk.Button(
            analysis_button_frame,
            text="Clear Analysis",
            command=lambda: self.clear_text(self.inspection_text),
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        clear_analysis_button.pack(side=tk.LEFT, padx=5)

    def analyze_last_packet(self):
        """Analyze the last captured packet in detail."""
        self.clear_text(self.inspection_text)
        if not self.captured_packets:
            self.insert_text(self.inspection_text, "No packets captured yet.\n")
            return

        packet = self.captured_packets[-1]  # Get the last packet
        try:
            # Basic packet information
            analysis = "=== Last Packet Analysis ===\n\n"
            analysis += f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            analysis += f"Packet Length: {len(packet)} bytes\n"
            analysis += f"Summary: {packet.summary()}\n\n"

            # Layer 2 (Data Link) Analysis
            if Ether in packet:
                analysis += "=== Layer 2 (Ethernet) ===\n"
                analysis += f"Source MAC: {packet[Ether].src}\n"
                analysis += f"Destination MAC: {packet[Ether].dst}\n"
                analysis += f"Ethernet Type: 0x{packet[Ether].type:04x}\n\n"

            # Layer 3 (Network) Analysis
            if IP in packet:
                analysis += "=== Layer 3 (IP) ===\n"
                analysis += f"Source IP: {packet[IP].src}\n"
                analysis += f"Destination IP: {packet[IP].dst}\n"
                analysis += f"Protocol: {packet[IP].proto}\n"
                analysis += f"TTL: {packet[IP].ttl}\n"
                analysis += f"IP Length: {packet[IP].len} bytes\n"
                analysis += f"IP Version: {packet[IP].version}\n\n"
            elif ARP in packet:
                analysis += "=== Layer 3 (ARP) ===\n"
                analysis += f"Operation: {'Request' if packet[ARP].op == 1 else 'Reply'}\n"
                analysis += f"Source MAC: {packet[ARP].hwsrc}\n"
                analysis += f"Destination MAC: {packet[ARP].hwdst}\n"
                analysis += f"Source IP: {packet[ARP].psrc}\n"
                analysis += f"Destination IP: {packet[ARP].pdst}\n\n"

            # Layer 4 (Transport) Analysis
            if TCP in packet:
                analysis += "=== Layer 4 (TCP) ===\n"
                analysis += f"Source Port: {packet[TCP].sport}\n"
                analysis += f"Destination Port: {packet[TCP].dport}\n"
                analysis += f"Sequence Number: {packet[TCP].seq}\n"
                analysis += f"Acknowledgment Number: {packet[TCP].ack}\n"
                analysis += "Flags:\n"
                analysis += f"  SYN: {bool(packet[TCP].flags.S)}\n"
                analysis += f"  ACK: {bool(packet[TCP].flags.A)}\n"
                analysis += f"  FIN: {bool(packet[TCP].flags.F)}\n"
                analysis += f"  RST: {bool(packet[TCP].flags.R)}\n"
                analysis += f"  PSH: {bool(packet[TCP].flags.P)}\n"
                analysis += f"Window Size: {packet[TCP].window}\n\n"
            elif UDP in packet:
                analysis += "=== Layer 4 (UDP) ===\n"
                analysis += f"Source Port: {packet[UDP].sport}\n"
                analysis += f"Destination Port: {packet[UDP].dport}\n"
                analysis += f"Length: {packet[UDP].len} bytes\n\n"
            elif ICMP in packet:
                analysis += "=== Layer 4 (ICMP) ===\n"
                analysis += f"Type: {packet[ICMP].type}\n"
                analysis += f"Code: {packet[ICMP].code}\n\n"

            # Application Layer Analysis
            if DNS in packet:
                analysis += "=== Application Layer (DNS) ===\n"
                if packet.haslayer(DNSQR):
                    analysis += "DNS Query:\n"
                    analysis += f"  Name: {packet[DNSQR].qname.decode()}\n"
                    analysis += f"  Type: {packet[DNSQR].qtype}\n"
                if packet.haslayer(DNSRR):
                    analysis += "DNS Response:\n"
                    analysis += f"  Name: {packet[DNSRR].rrname.decode()}\n"
                    analysis += f"  Type: {packet[DNSRR].type}\n"
                    analysis += f"  TTL: {packet[DNSRR].ttl}\n"
                    analysis += f"  Data: {packet[DNSRR].rdata}\n\n"

            # Payload Analysis
            if Raw in packet:
                analysis += "=== Payload ===\n"
                raw_payload = packet[Raw].load
                try:
                    # Try to decode as ASCII
                    decoded_payload = raw_payload.decode('ascii', errors='replace')
                    analysis += f"ASCII Payload: {decoded_payload}\n"
                except:
                    # If ASCII decoding fails, show hex dump
                    analysis += f"Hex Payload: {raw_payload.hex()}\n"
                analysis += f"Payload Length: {len(raw_payload)} bytes\n\n"

            # Security Analysis
            analysis += "=== Security Analysis ===\n"
            # Check for potential security issues
            if TCP in packet:
                if packet[TCP].flags.S and not packet[TCP].flags.A:
                    analysis += "! Possible SYN scan detected\n"
                if all(flag == 0 for flag in packet[TCP].flags):
                    analysis += "! NULL scan detected\n"
                if packet[TCP].flags.F and not packet[TCP].flags.A:
                    analysis += "! FIN scan detected\n"
            if IP in packet:
                if packet[IP].ttl < 10:
                    analysis += "! Low TTL value - possible traceroute or TTL-based attack\n"

            self.insert_text(self.inspection_text, analysis)

        except Exception as e:
            error_msg = f"Error analyzing packet: {str(e)}\n"
            self.insert_text(self.inspection_text, error_msg)
            logging.error(f"Error in packet analysis: {e}")

    def analyze_all_packets(self):
        """Analyze all captured packets and show statistics."""
        self.clear_text(self.inspection_text)
        if not self.captured_packets:
            self.insert_text(self.inspection_text, "No packets captured yet.\n")
            return

        try:
            analysis = "=== Packet Analysis Summary ===\n\n"
            
            # Basic Statistics
            total_packets = len(self.captured_packets)
            total_bytes = sum(len(p) for p in self.captured_packets)
            avg_size = total_bytes / total_packets if total_packets > 0 else 0
            
            analysis += f"Total Packets: {total_packets}\n"
            analysis += f"Total Bytes: {total_bytes}\n"
            analysis += f"Average Packet Size: {avg_size:.2f} bytes\n\n"
            
            # Protocol Distribution
            protocols = {
                'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'DNS': 0,
                'Other': 0
            }
            
            tcp_ports = {}
            udp_ports = {}
            ip_addresses = {'src': {}, 'dst': {}}
            
            for packet in self.captured_packets:
                # Count protocols
                if TCP in packet:
                    protocols['TCP'] += 1
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    tcp_ports[sport] = tcp_ports.get(sport, 0) + 1
                    tcp_ports[dport] = tcp_ports.get(dport, 0) + 1
                elif UDP in packet:
                    protocols['UDP'] += 1
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    udp_ports[sport] = udp_ports.get(sport, 0) + 1
                    udp_ports[dport] = udp_ports.get(dport, 0) + 1
                elif ICMP in packet:
                    protocols['ICMP'] += 1
                elif ARP in packet:
                    protocols['ARP'] += 1
                else:
                    protocols['Other'] += 1
                
                if DNS in packet:
                    protocols['DNS'] += 1
                
                # Count IP addresses
                if IP in packet:
                    src = packet[IP].src
                    dst = packet[IP].dst
                    ip_addresses['src'][src] = ip_addresses['src'].get(src, 0) + 1
                    ip_addresses['dst'][dst] = ip_addresses['dst'].get(dst, 0) + 1
            
            # Protocol Distribution
            analysis += "=== Protocol Distribution ===\n"
            for proto, count in protocols.items():
                if count > 0:
                    percentage = (count / total_packets) * 100
                    analysis += f"{proto}: {count} ({percentage:.1f}%)\n"
            analysis += "\n"
            
            # Top Source IP Addresses
            analysis += "=== Top Source IP Addresses ===\n"
            top_sources = sorted(ip_addresses['src'].items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_sources:
                percentage = (count / total_packets) * 100
                analysis += f"{ip}: {count} ({percentage:.1f}%)\n"
            analysis += "\n"
            
            # Top Destination IP Addresses
            analysis += "=== Top Destination IP Addresses ===\n"
            top_destinations = sorted(ip_addresses['dst'].items(), key=lambda x: x[1], reverse=True)[:5]
            for ip, count in top_destinations:
                percentage = (count / total_packets) * 100
                analysis += f"{ip}: {count} ({percentage:.1f}%)\n"
            analysis += "\n"
            
            # Top TCP Ports
            if tcp_ports:
                analysis += "=== Top TCP Ports ===\n"
                top_tcp = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                for port, count in top_tcp:
                    percentage = (count / protocols['TCP']) * 100 if protocols['TCP'] > 0 else 0
                    service = self.get_common_port_service(port)
                    analysis += f"Port {port} ({service}): {count} ({percentage:.1f}%)\n"
                analysis += "\n"
            
            # Top UDP Ports
            if udp_ports:
                analysis += "=== Top UDP Ports ===\n"
                top_udp = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                for port, count in top_udp:
                    percentage = (count / protocols['UDP']) * 100 if protocols['UDP'] > 0 else 0
                    service = self.get_common_port_service(port)
                    analysis += f"Port {port} ({service}): {count} ({percentage:.1f}%)\n"
                analysis += "\n"
            
            # Security Analysis
            analysis += "=== Security Analysis ===\n"
            security_issues = []
            
            # Check for potential port scans
            if len(tcp_ports) > 100:
                security_issues.append("Possible port scan detected (high number of TCP ports)")
            if len(udp_ports) > 100:
                security_issues.append("Possible port scan detected (high number of UDP ports)")
            
            # Check for suspicious patterns
            syn_count = sum(1 for p in self.captured_packets if TCP in p and p[TCP].flags.S and not p[TCP].flags.A)
            if syn_count > 10:
                security_issues.append(f"Possible SYN scan detected ({syn_count} SYN packets without ACK)")
            
            if security_issues:
                for issue in security_issues:
                    analysis += f"! {issue}\n"
            else:
                analysis += "No significant security issues detected\n"
            
            self.insert_text(self.inspection_text, analysis)
            
        except Exception as e:
            error_msg = f"Error analyzing packets: {str(e)}\n"
            self.insert_text(self.inspection_text, error_msg)
            logging.error(f"Error in packet analysis: {e}")

    def get_common_port_service(self, port):
        """Return common service name for well-known ports."""
        common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3389: 'RDP'
        }
        return common_ports.get(port, 'Unknown')

    def start_sniffing_thread(self):
        """Start the packet sniffing in a separate thread."""
        self.sniffing = True
        sniffing_thread = threading.Thread(target=self.start_sniffing, args=(self.output_text,), daemon=True)
        sniffing_thread.start()

    def start_sniffing(self, output_text):
        """Start capturing packets."""
        try:
            self.clear_terminal()  # Clear terminal before starting capture
            self.print_capture_banner()  # Print capture start banner
            
            self.start_time = time.time()
            self.update_gui()
            
            # Check for admin privileges
            if platform.system() == 'Windows':
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("\n[ERROR] Administrative privileges required!")
                    print("Please run the application as administrator.\n")
                    messagebox.showerror("Permission Error", "This application requires administrative privileges. Please run as administrator.")
                    return
            else:
                if not os.geteuid() == 0:
                    print("\n[ERROR] Root privileges required!")
                    print("Please run the application with sudo.\n")
                    messagebox.showerror("Permission Error", "This application requires administrative privileges.")
                    return
            
            print("\n[INFO] Starting packet capture...")
            print("[INFO] Press Ctrl+C in the GUI to stop capturing.\n")
            
            # Start packet capture
            sniff(prn=self.packet_callback, store=False, filter=self.get_filter_string())
            
        except Exception as e:
            error_msg = f"\n[ERROR] Failed to start packet capture: {str(e)}"
            print(error_msg)
            logging.error(f"Error starting packet capture: {e}")
            messagebox.showerror("Error", f"Failed to start packet capture: {str(e)}")

    def get_filter_string(self):
        """Get the filter string based on selected protocol."""
        protocol = self.protocol_var.get()
        if protocol == "All":
            return ""
        elif protocol == "DNS":
            return "(udp port 53) or (tcp port 53)"  # Capture both UDP and TCP DNS traffic
        elif protocol == "ARP":
            return "arp"
        else:
            return protocol.lower()

    def print_capture_banner(self):
        """Print a banner when capture starts."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                   Packet Capture Started                      ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)

    def update_gui(self):
        """Update the GUI with the latest statistics."""
        try:
            # Batch updates to reduce GUI overhead
            updates = {
                self.packet_count_label: f"Packets Captured: {self.packet_count}",
                self.total_bytes_label: f"Total Bytes: {self.total_bytes}",
                self.icmp_count_label: f"ICMP Packets: {self.protocol_count['ICMP']}",
                self.tcp_count_label: f"TCP Packets: {self.protocol_count['TCP']}",
                self.udp_count_label: f"UDP Packets: {self.protocol_count['UDP']}",
                self.arp_count_label: f"ARP Packets: {self.protocol_count['ARP']}",
                self.dns_count_label: f"DNS Packets: {self.protocol_count['DNS']}"
            }
            
            for label, text in updates.items():
                label.config(text=text)
            
            # Reduce update frequency for better performance
            self.root.after(2000, self.update_gui)  # Update every 2 seconds
            
        except Exception as e:
            logging.error(f"Error updating GUI: {e}")

    def update_statistics(self):
        """Update packet statistics."""
        try:
            if self.packet_sizes:
                avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
                max_size = max(self.packet_sizes)
                min_size = min(self.packet_sizes)
                
                self.average_packet_size_label.config(
                    text=f"Average Packet Size: {avg_size:.2f} bytes")
                self.max_packet_size_label.config(
                    text=f"Max Packet Size: {max_size} bytes")
                self.min_packet_size_label.config(
                    text=f"Min Packet Size: {min_size} bytes")
        except Exception as e:
            logging.error(f"Error updating statistics: {e}")

    def stop_sniffing(self):
        """Stop the packet sniffing."""
        self.sniffing = False
        self.clear_terminal()
        print("\n" + "═" * 60)
        print("Packet Capture Stopped")
        print("Summary:")
        print(f"Total Packets: {self.packet_count}")
        print(f"TCP Packets: {self.protocol_count['TCP']}")
        print(f"UDP Packets: {self.protocol_count['UDP']}")
        print(f"ICMP Packets: {self.protocol_count['ICMP']}")
        print(f"ARP Packets: {self.protocol_count['ARP']}")
        print(f"DNS Packets: {self.protocol_count['DNS']}")
        print("═" * 60 + "\n")
        
        self.output_text.insert(tk.END, "Sniffing stopped.\n")
        self.output_text.see(tk.END)

    def packet_callback(self, packet):
        """Process captured packets."""
        try:
            if not self.sniffing:
                return

            # Get current time relative to start
            current_time = time.time() - self.start_time
            
            # Format console output for packet info
            console_output = "\r" + "─" * 60 + "\n"
            console_output += f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            # Create packet details dictionary for logging
            packet_details = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "protocol": "Unknown",
                "src": None,
                "dst": None,
                "src_port": None,
                "dst_port": None,
                "length": len(packet),
                "payload": None
            }
            
            if IP in packet:
                packet_details["protocol"] = "IP"
                packet_details["src"] = packet[IP].src
                packet_details["dst"] = packet[IP].dst
                console_output += f"Protocol: {packet.proto}\n"
                console_output += f"Source IP: {packet[IP].src}\n"
                console_output += f"Destination IP: {packet[IP].dst}\n"
                
                if TCP in packet:
                    packet_details["protocol"] = "TCP"
                    packet_details["src_port"] = packet[TCP].sport
                    packet_details["dst_port"] = packet[TCP].dport
                    console_output += f"Source Port: {packet[TCP].sport}\n"
                    console_output += f"Destination Port: {packet[TCP].dport}\n"
                elif UDP in packet:
                    packet_details["protocol"] = "UDP"
                    packet_details["src_port"] = packet[UDP].sport
                    packet_details["dst_port"] = packet[UDP].dport
                    console_output += f"Source Port: {packet[UDP].sport}\n"
                    console_output += f"Destination Port: {packet[UDP].dport}\n"
                elif ICMP in packet:
                    packet_details["protocol"] = "ICMP"
                elif packet.haslayer(DNS):
                    packet_details["protocol"] = "DNS"
            elif ARP in packet:
                packet_details["protocol"] = "ARP"
                packet_details["src"] = packet[ARP].hwsrc
                packet_details["dst"] = packet[ARP].hwdst
                console_output += f"Protocol: ARP\n"
                console_output += f"Source MAC: {packet[ARP].hwsrc}\n"
                console_output += f"Destination MAC: {packet[ARP].hwdst}\n"
            
            # Add payload if present
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                    packet_details["payload"] = payload
                except:
                    packet_details["payload"] = packet[Raw].load.hex()
            
            console_output += "─" * 60 + "\n"
            
            # Print to console with clean formatting
            sys.stdout.write(console_output)
            sys.stdout.flush()

            # Log packet details to file
            self.log_packet(packet_details)

            # Process the packet and update protocol-specific counts
            packet_protocol = packet_details["protocol"]
            if packet_protocol in self.protocol_current_count:
                self.protocol_current_count[packet_protocol] += 1
                self.protocol_times[packet_protocol].append(current_time)
                self.protocol_counts[packet_protocol].append(self.protocol_current_count[packet_protocol])

            # Always update the "All" protocol statistics
            self.protocol_current_count['All'] += 1
            self.protocol_times['All'].append(current_time)
            self.protocol_counts['All'].append(self.protocol_current_count['All'])

            # Format packet information for display
            packet_info = f"Time: {packet_details['timestamp']}\n"
            packet_info += f"Protocol: {packet_details['protocol']}\n"
            if packet_details['src']:
                packet_info += f"Source: {packet_details['src']}\n"
            if packet_details['dst']:
                packet_info += f"Destination: {packet_details['dst']}\n"
            if packet_details['src_port']:
                packet_info += f"Source Port: {packet_details['src_port']}\n"
            if packet_details['dst_port']:
                packet_info += f"Destination Port: {packet_details['dst_port']}\n"
            packet_info += "-" * 50 + "\n"

            # Display packet if it matches the filter or if "All" is selected
            if self.protocol_var.get() == "All" or self.protocol_var.get() == packet_protocol:
                self.insert_text(self.output_text, packet_info)

            # Update packet count label
            self.packet_count += 1
            self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")

            # Store packet for analysis
            self.captured_packets.append(packet)

            # Update protocol counts in the statistics
            if packet_protocol in self.protocol_count:
                self.protocol_count[packet_protocol] = self.protocol_current_count[packet_protocol]

        except Exception as e:
            error_msg = f"\n[ERROR] Packet processing error: {str(e)}\n"
            print(error_msg)
            logging.error(f"Error in packet callback: {e}")

    def log_packet(self, packet_details):
        """Log packet details to a JSON file."""
        try:
            # Ensure the log directory exists
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # Append to log file with proper line ending
            with open(self.log_file, "a", encoding='utf-8') as f:
                json.dump(packet_details, f)
                f.write('\n')  # Add newline after each entry
                
        except Exception as e:
            logging.error(f"Error logging packet: {e}")

    def view_packet_log(self):
        """Display the packet log in the logging tab with pagination."""
        self.clear_text(self.logging_text)
        try:
            # Initialize pagination if not already done
            if not hasattr(self, 'current_page'):
                self.current_page = 0
            if not hasattr(self, 'logs_per_page'):
                self.logs_per_page = 50  # Show fewer logs per page for better readability

            # Check if log file exists
            if not os.path.exists(self.log_file):
                self.insert_text(self.logging_text, "No packet log found. Start capturing packets to create a log.\n")
                return

            # Read the entire file to count total entries
            with open(self.log_file, "r", encoding='utf-8') as f:
                all_lines = list(filter(None, f.readlines()))  # Remove empty lines
            
            if not all_lines:
                self.insert_text(self.logging_text, "Packet log is empty. No packets have been captured yet.\n")
                return

            total_logs = len(all_lines)
            total_pages = max(1, (total_logs + self.logs_per_page - 1) // self.logs_per_page)
            self.total_pages = total_pages  # Store for jump_to_page function

            # Ensure current page is valid
            self.current_page = min(self.current_page, total_pages - 1)
            self.current_page = max(0, self.current_page)

            # Calculate start and end indices for current page
            start_idx = self.current_page * self.logs_per_page
            end_idx = min(start_idx + self.logs_per_page, total_logs)

            # Display page information
            page_info = f"Showing entries {start_idx + 1}-{end_idx} of {total_logs}\n"
            page_info += f"Page {self.current_page + 1} of {total_pages}\n"
            page_info += "=" * 60 + "\n\n"
            self.insert_text(self.logging_text, page_info)

            # Display current page of logs with formatting
            for line in all_lines[start_idx:end_idx]:
                try:
                    # Parse JSON and format output
                    packet_data = json.loads(line.strip())
                    formatted_output = self.format_packet_log_entry(packet_data)
                    self.insert_text(self.logging_text, formatted_output)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing JSON: {e}")
                    continue
                except Exception as e:
                    logging.error(f"Error processing log entry: {e}")
                    continue

            # Update or create pagination controls
            self.update_pagination_controls(total_pages)

        except Exception as e:
            error_msg = f"Error loading packet log: {str(e)}\n"
            self.insert_text(self.logging_text, error_msg)
            logging.error(f"Error loading packet log: {e}")

    def update_pagination_controls(self, total_pages):
        """Update or create pagination controls."""
        try:
            if not hasattr(self, 'pagination_frame'):
                # Create pagination frame and controls
                self.create_pagination_controls(total_pages)
            else:
                # Update existing controls
                self.prev_button.config(state=tk.DISABLED if self.current_page == 0 else tk.NORMAL)
                self.next_button.config(state=tk.DISABLED if self.current_page >= total_pages - 1 else tk.NORMAL)
                self.page_label.config(text=f"Page {self.current_page + 1} of {total_pages}")
        except Exception as e:
            logging.error(f"Error updating pagination controls: {e}")

    def create_pagination_controls(self, total_pages):
        """Create pagination controls."""
        self.pagination_frame = ttk.Frame(self.logging_frame)
        self.pagination_frame.pack(fill=tk.X, pady=5)

        # Previous page button
        self.prev_button = tk.Button(
            self.pagination_frame,
            text="◄ Previous",
            command=self.previous_page,
            bg="#007BFF",
            fg="white",
            font=("Arial", 10),
            state=tk.DISABLED if self.current_page == 0 else tk.NORMAL
        )
        self.prev_button.pack(side=tk.LEFT, padx=5)

        # Page indicator label
        self.page_label = tk.Label(
            self.pagination_frame,
            text=f"Page {self.current_page + 1} of {total_pages}",
            font=("Arial", 10)
        )
        self.page_label.pack(side=tk.LEFT, padx=5)

        # Next page button
        self.next_button = tk.Button(
            self.pagination_frame,
            text="Next ►",
            command=self.next_page,
            bg="#007BFF",
            fg="white",
            font=("Arial", 10),
            state=tk.DISABLED if self.current_page >= total_pages - 1 else tk.NORMAL
        )
        self.next_button.pack(side=tk.LEFT, padx=5)

        # Jump to page controls
        self.jump_label = tk.Label(
            self.pagination_frame,
            text="Go to page:",
            font=("Arial", 10)
        )
        self.jump_label.pack(side=tk.LEFT, padx=5)

        self.jump_entry = tk.Entry(
            self.pagination_frame,
            width=5,
            font=("Arial", 10)
        )
        self.jump_entry.pack(side=tk.LEFT, padx=2)

        self.jump_button = tk.Button(
            self.pagination_frame,
            text="Go",
            command=self.jump_to_page,
            bg="#28a745",
            fg="white",
            font=("Arial", 10)
        )
        self.jump_button.pack(side=tk.LEFT, padx=5)

    def format_packet_log_entry(self, packet_data):
        """Format a packet log entry for display."""
        output = "╔" + "═" * 58 + "╗\n"
        output += f"║ Timestamp: {packet_data.get('timestamp', 'N/A'):<47}║\n"
        output += f"║ Protocol: {packet_data.get('protocol', 'N/A'):<49}║\n"
        
        if packet_data.get('src'):
            output += f"║ Source: {packet_data['src']:<51}║\n"
        if packet_data.get('dst'):
            output += f"║ Destination: {packet_data['dst']:<47}║\n"
        if packet_data.get('src_port'):
            output += f"║ Source Port: {packet_data['src_port']:<47}║\n"
        if packet_data.get('dst_port'):
            output += f"║ Destination Port: {packet_data['dst_port']:<43}║\n"
        if packet_data.get('length'):
            output += f"║ Length: {packet_data['length']:<51}║\n"
        
        payload = packet_data.get('payload', 'No payload')
        if payload != 'No payload':
            output += "║ Payload:                                                    ║\n"
            # Split payload into chunks of 50 characters
            payload = payload[:200]  # Limit payload display
            chunks = [payload[i:i+50] for i in range(0, len(payload), 50)]
            for chunk in chunks:
                output += f"║ {chunk:<58}║\n"
        
        output += "╚" + "═" * 58 + "╝\n\n"
        return output

    def jump_to_page(self):
        """Jump to a specific page number."""
        try:
            page_num = int(self.jump_entry.get()) - 1  # Convert to 0-based index
            if 0 <= page_num < self.total_pages:
                self.current_page = page_num
                self.view_packet_log()
            else:
                messagebox.showwarning("Invalid Page", f"Please enter a page number between 1 and {self.total_pages}")
        except ValueError:
            messagebox.showwarning("Invalid Input", "Please enter a valid page number")
        self.jump_entry.delete(0, tk.END)  # Clear the entry after use

    def previous_page(self):
        """Go to previous page of logs."""
        if self.current_page > 0:
            self.current_page -= 1
            self.view_packet_log()

    def next_page(self):
        """Go to next page of logs."""
        self.current_page += 1
        self.view_packet_log()

    def update_view_log(self):
        """Refresh the displayed packet log."""
        self.current_page = 0  # Reset to first page
        self.view_packet_log()

    def export_packet_log(self):
        """Export the packet log to a user-defined file in a selected directory."""
        try:
            # Open a file dialog to select the save location and filename
            file_path = tkinter.filedialog.asksaveasfilename(
                title="Export Packet Log",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile="exported_packet_log.json"  # Default filename
            )
            if file_path:  # Check if the user selected a file
                # Copy file in chunks to prevent memory issues
                with open(self.log_file, "r") as source, open(file_path, "w") as target:
                    while True:
                        chunk = source.read(8192)  # Read 8KB at a time
                        if not chunk:
                            break
                        target.write(chunk)
                messagebox.showinfo("Export Successful", f"Packet log exported to '{file_path}'.")
            else:
                messagebox.showwarning("Export Cancelled", "Export operation was cancelled.")
        except FileNotFoundError:
            messagebox.showerror("Export Error", "No packet log found to export.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export log: {str(e)}")

    def clear_output(self):
        """Clear the output text area."""
        self.clear_text(self.output_text)
        self.packet_count = 0
        self.packet_count_label.config(text="Packets Captured: 0")
        self.captured_packets.clear()

    def clear_cache(self):
        """Clear the captured packets and reset statistics."""
        try:
            self.captured_packets.clear()
            self.packet_count = 0
            self.total_bytes = 0
            self.packet_sizes.clear()
            self.packet_times.clear()  # Clear time data
            self.packet_counts.clear()  # Clear count data
            gc.collect()  # Force garbage collection
            
            # Reset protocol counts
            self.protocol_count = {key: 0 for key in self.protocol_count}
            
        except Exception as e:
            logging.error(f"Error clearing cache: {e}")

    def toggle_dark_mode(self):
        """Toggle between light and dark mode."""
        print("Toggle Dark Mode clicked.")  # Debugging statement

        if not self.is_dark_mode:
            # Switch to dark mode
            self.root.configure(bg="#2E2E2E")  # Dark background
            self.style.configure("TFrame", background="#2E2E2E")  # Update style for dark mode

            # Update all tabs
            for tab in [self.packet_filter_tab, self.logging_tab, self.inspection_tab, self.statistics_tab]:
                tab.configure(bg="#2E2E2E")  # Set tab background to dark

            # Update labels and text areas
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Label):
                    widget.configure(bg="#2E2E2E", fg="white")
                elif isinstance(widget, scrolledtext.ScrolledText):
                    widget.configure(bg="#1E1E1E", fg="white")
                elif isinstance(widget, tk.Button):
                    widget.configure(bg="#007BFF", fg="white")

            self.is_dark_mode = True  # Update theme state
            print("Switched to dark mode.")  # Debugging statement
        else:
            # Switch to light mode
            self.root.configure(bg="#FFFFFF")  # Light background
            self.style.configure("TFrame", background="#FFFFFF")  # Update style for light mode

            # Update all tabs
            for tab in [self.packet_filter_tab, self.logging_tab, self.inspection_tab, self.statistics_tab]:
                tab.configure(bg="#FFFFFF")  # Set tab background to light

            # Update labels and text areas
            for widget in self.root.winfo_children():
                if isinstance(widget, tk.Label):
                    widget.configure(bg="#FFFFFF", fg="black")
                elif isinstance(widget, scrolledtext.ScrolledText):
                    widget.configure(bg="#FFFFFF", fg="black")
                elif isinstance(widget, tk.Button):
                    widget.configure(bg="#007BFF", fg="white")

            self.is_dark_mode = False  # Update theme state
            print("Switched to light mode.")  # Debugging statement

    def validate_ip_address(self, ip_address):
        """Validate IP address format."""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, ip_address):
            return False
        # Check each octet is in valid range
        octets = ip_address.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)

    def ping(self):
        """Ping a known IP address to generate ICMP packets."""
        ip_address = self.ip_entry.get().strip()
        if not self.validate_ip_address(ip_address):
            messagebox.showerror("Invalid IP", "Please enter a valid IP address (e.g., 192.168.1.1)")
            return
        try:
            # Determine the appropriate ping command based on the OS
            if platform.system().lower() == "windows":
                # Windows uses -n to specify the number of packets
                output = subprocess.check_output(["ping", ip_address, "-n", "4"], stderr=subprocess.STDOUT, universal_newlines=True)
            else:
                # Unix-like systems use -c to specify the number of packets
                output = subprocess.check_output(["ping", ip_address, "-c", "4"], stderr=subprocess.STDOUT, universal_newlines=True)

            self.output_text.insert(tk.END, f"Ping Output:\n{output}\n")
            self.output_text.see(tk.END)  # Scroll to the end of the text area
        except subprocess.CalledProcessError as e:
            self.output_text.insert(tk.END, f"Error pinging {ip_address}:\n{e.output}\n")
            self.output_text.see(tk.END)  # Scroll to the end of the text area

    def create_tooltip(self, widget, text):
        tooltip = tk.Toplevel(widget)
        tooltip.wm_overrideredirect(True)
        tooltip.wm_geometry(f"+{widget.winfo_rootx()+20}+{widget.winfo_rooty()+20}")
        label = tk.Label(tooltip, text=text, background="lightyellow", relief="solid", borderwidth=1)
        label.pack()

        def hide_tooltip(event):
            tooltip.withdraw()

        widget.bind("<Enter>", lambda event: tooltip.deiconify())
        widget.bind("<Leave>", hide_tooltip)

    def update_status(self, message):
        self.status_bar.config(text=message)

    def export_to_csv(self):
        """Export captured packets to CSV file."""
        try:
            file_path = tkinter.filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if not file_path:
                return

            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                # Write header
                writer.writerow([
                    'Timestamp',
                    'Protocol',
                    'Source IP',
                    'Destination IP',
                    'Source Port',
                    'Destination Port',
                    'Length',
                    'Source MAC',
                    'Destination MAC',
                    'TTL',
                    'Flags'
                ])

                # Write packet data
                for packet in self.captured_packets:
                    row = self._format_packet_for_csv(packet)
                    writer.writerow(row)

            messagebox.showinfo("Success", "Packets exported to CSV file successfully!")
            
        except Exception as e:
            logging.error(f"Error exporting to CSV: {e}")
            messagebox.showerror("Error", f"Failed to export to CSV: {str(e)}")

    def _format_packet_for_csv(self, packet):
        """Format a packet's data for CSV export."""
        try:
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            protocol = 'Unknown'
            src_ip = dst_ip = 'N/A'
            src_port = dst_port = 'N/A'
            length = len(packet)
            src_mac = dst_mac = 'N/A'
            ttl = 'N/A'
            flags = 'N/A'

            # Get protocol and IP information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ttl = packet[IP].ttl
                
                if TCP in packet:
                    protocol = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    # Get TCP flags
                    flags = []
                    if packet[TCP].flags.S: flags.append('SYN')
                    if packet[TCP].flags.A: flags.append('ACK')
                    if packet[TCP].flags.F: flags.append('FIN')
                    if packet[TCP].flags.R: flags.append('RST')
                    if packet[TCP].flags.P: flags.append('PSH')
                    flags = '|'.join(flags) if flags else 'None'
                    
                elif UDP in packet:
                    protocol = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    
                elif ICMP in packet:
                    protocol = 'ICMP'
                    
                if packet.haslayer(DNS):
                    protocol = 'DNS'

            elif ARP in packet:
                protocol = 'ARP'
                src_mac = packet[ARP].hwsrc
                dst_mac = packet[ARP].hwdst
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst

            # If Ethernet layer exists, get MAC addresses
            if Ether in packet:
                src_mac = packet[Ether].src
                dst_mac = packet[Ether].dst

            return [
                timestamp,
                protocol,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                length,
                src_mac,
                dst_mac,
                ttl,
                flags
            ]

        except Exception as e:
            logging.error(f"Error formatting packet for CSV: {e}")
            return ['Error'] * 11  # Return empty row in case of error

    def clear_graph(self):
        """Clear the graph data and reset protocol statistics."""
        try:
            # Clear protocol times and counts
            for protocol in self.protocol_times:
                self.protocol_times[protocol].clear()
                self.protocol_counts[protocol].clear()
                self.protocol_current_count[protocol] = 0

            # Reset the graph
            self.ax.clear()
            self.ax.set_title("Live Packet Statistics Over Time", fontsize=14)
            self.ax.set_xlabel("Time (s)", fontsize=12)
            self.ax.set_ylabel("Count", fontsize=12)
            self.ax.set_xlim(0, 60)
            self.ax.set_ylim(0, 100)
            self.ax.grid(True, linestyle='--', alpha=0.7)
            
            # Update the canvas
            self.canvas.draw()

            # Reset start time
            self.start_time = time.time()

            # Update labels
            self.update_statistics()
            
            # Show success message
            messagebox.showinfo("Success", "Graph data has been cleared!")
            
        except Exception as e:
            logging.error(f"Error clearing graph: {e}")
            messagebox.showerror("Error", f"Failed to clear graph: {str(e)}")

    def insert_text(self, text_widget, text):
        """Safely insert text into a read-only text widget."""
        text_widget.config(state='normal')  # Temporarily enable editing
        text_widget.insert(tk.END, text)
        text_widget.see(tk.END)  # Auto-scroll to bottom
        text_widget.config(state='disabled')  # Make read-only again

    def clear_text(self, text_widget):
        """Safely clear a read-only text widget."""
        text_widget.config(state='normal')  # Temporarily enable editing
        text_widget.delete(1.0, tk.END)
        text_widget.config(state='disabled')  # Make read-only again

    def create_statistics_tab(self):
        """Create the content for the Live Statistics tab."""
        # Create a frame for the graph
        graph_frame = ttk.Frame(self.statistics_frame)
        graph_frame.pack(expand=True, fill=tk.BOTH, pady=10)

        # Initialize the live graph for statistics
        self.fig, self.ax = plt.subplots(figsize=(12, 6))  # Increase figure size
        self.ax.set_title("Live Packet Statistics Over Time", fontsize=14)
        self.ax.set_xlabel("Time (s)", fontsize=12)
        self.ax.set_ylabel("Count", fontsize=12)
        self.ax.set_xlim(0, 60)  # Set x-axis limit for 60 seconds
        self.ax.set_ylim(0, 100)  # Set y-axis limit for counts
        self.ax.grid(True, linestyle='--', alpha=0.7)  # Add grid

        # Create a canvas to embed the plot in Tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Add clear graph button
        clear_graph_button = tk.Button(
            graph_frame,
            text="Clear Graph",
            command=self.clear_graph,
            bg="#dc3545",
            fg="white",
            font=("Arial", 12),
            padx=20,
            pady=5
        )
        clear_graph_button.pack(pady=5)

        # Schedule the first graph update
        self.root.after(1000, self.update_graph)  # Start updating after 1 second

        # Create a frame for statistics labels
        stats_frame = ttk.Frame(self.statistics_frame)
        stats_frame.pack(fill=tk.X, padx=10, pady=5)

        # Create a centered container for statistics
        center_stats = ttk.Frame(stats_frame)
        center_stats.pack(expand=True)

        # Now add the statistics labels below the graph
        self.total_packets_label = tk.Label(
            center_stats,
            text="Total Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.total_packets_label.pack(pady=5)

        self.total_bytes_label = tk.Label(
            center_stats,
            text="Total Bytes: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.total_bytes_label.pack(pady=5)

        self.average_packet_size_label = tk.Label(
            center_stats,
            text="Average Packet Size: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.average_packet_size_label.pack(pady=5)

        self.tcp_count_label = tk.Label(
            center_stats,
            text="TCP Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.tcp_count_label.pack(pady=5)

        self.udp_count_label = tk.Label(
            center_stats,
            text="UDP Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.udp_count_label.pack(pady=5)

        self.icmp_count_label = tk.Label(
            center_stats,
            text="ICMP Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.icmp_count_label.pack(pady=5)

        self.arp_count_label = tk.Label(
            center_stats,
            text="ARP Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.arp_count_label.pack(pady=5)

        self.dns_count_label = tk.Label(
            center_stats,
            text="DNS Packets: 0",
            bg="#FFFFFF",
            fg="black",
            font=("Arial", 12)
        )
        self.dns_count_label.pack(pady=5)

    def update_graph(self):
        """Update the live graph with the latest statistics."""
        try:
            # Clear the axes for new data
            self.ax.clear()

            # Get the selected protocol
            selected_protocol = self.protocol_var.get()
            
            # Get the data for plotting
            times = self.protocol_times[selected_protocol]
            counts = self.protocol_counts[selected_protocol]
            
            if len(times) > 0:  # Only plot if we have data
                # Plot packet counts
                self.ax.plot(times, counts, 
                           label=f'{selected_protocol} Packets',
                           color='blue',
                           linewidth=2,
                           marker='o',  # Add markers for better visibility
                           markersize=4,
                           markerfacecolor='white')
                
                # Calculate and plot moving average if enough data points
                if len(counts) > 5:
                    window_size = 5
                    moving_avg = []
                    for i in range(len(counts) - window_size + 1):
                        window_avg = sum(counts[i:i+window_size]) / window_size
                        moving_avg.append(window_avg)
                    
                    moving_avg_times = times[window_size-1:]
                    self.ax.plot(moving_avg_times, 
                               moving_avg,
                               label=f'Moving Average (5s)',
                               color='red',
                               linestyle='--',
                               linewidth=2)

                # Dynamic axis limits
                if len(times) > 0:
                    current_time = times[-1]
                    # Show last 60 seconds of data
                    x_min = max(0, current_time - 60)
                    x_max = current_time + 5  # Add 5 second buffer
                    
                    # Dynamic y-axis limit based on maximum count
                    y_max = max(max(counts) * 1.2, 10)  # At least show up to 10
                    
                    self.ax.set_xlim(x_min, x_max)
                    self.ax.set_ylim(0, y_max)
                else:
                    # Default limits if no data
                    self.ax.set_xlim(0, 60)
                    self.ax.set_ylim(0, 10)

                # Improve grid appearance
                self.ax.grid(True, linestyle='--', alpha=0.7)
                
                # Set title and labels with larger font
                self.ax.set_title(f"Live {selected_protocol} Packet Statistics", 
                                fontsize=14, 
                                pad=10)
                self.ax.set_xlabel("Time (seconds)", fontsize=12)
                self.ax.set_ylabel("Packet Count", fontsize=12)
                
                # Improve legend
                self.ax.legend(loc='upper left', 
                             fontsize=10, 
                             facecolor='white', 
                             edgecolor='gray',
                             framealpha=0.8)
                
                # Update the canvas
                self.canvas.draw()

        except Exception as e:
            logging.error(f"Error updating graph: {e}")
        finally:
            # Schedule the next update
            if self.sniffing:
                self.root.after(1000, self.update_graph)  # Update every second
            else:
                self.root.after(2000, self.update_graph)  # Check less frequently when not sniffing

    def clear_terminal(self):
        """Clear the terminal screen based on the operating system."""
        if platform.system().lower() == "windows":
            os.system('cls')
        else:
            os.system('clear')

    def print_welcome_banner(self):
        """Print a welcome banner with application information."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                      SniffWork v1.0                          ║
║           Network Packet Analyzer and Monitor                ║
╚══════════════════════════════════════════════════════════════╝
"""
        print(banner)
        print("Initializing application...")
        print("Please wait while the GUI loads...\n")

if __name__ == "__main__":
    # Clear terminal at startup
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear')
        
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

    #python "c:\Users\jowey\Documents\Python Codes\SniffWork\Network Sniffer.py"