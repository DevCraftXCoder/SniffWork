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
from matplotlib.figure import Figure

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
        
        # Configure window properties
        self.root.configure(bg="#2E2E2E")  # Dark background
        
        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        # Calculate window size (60% width, 75% height)
        window_width = int(screen_width * 0.60)
        window_height = int(screen_height * 0.75)
        
        # Calculate position for center of screen
        position_x = (screen_width - window_width) // 2
        position_y = (screen_height - window_height) // 2
        
        # Set window size and position
        self.root.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")
        
        # Set window icon and configure
        try:
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

        # Add the Toggle Mode option
        view_menu.add_command(label="Toggle Modes", command=self.toggle_dark_mode)  # Changed label to be more generic

        # Create status bar frame
        self.status_frame = tk.Frame(self.root, bg="#2E2E2E")
        self.status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Create status bar with loading indicator
        self.status_bar = tk.Label(
            self.status_frame,
            text="Ready",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg="#2E2E2E",
            fg="white",
            padx=10
        )
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Create loading indicator label
        self.loading_label = tk.Label(
            self.status_frame,
            text="",
            bg="#2E2E2E",
            fg="#00ff00",
            font=("Helvetica", 10),
            padx=10
        )
        self.loading_label.pack(side=tk.RIGHT)
        
        # Initialize loading state
        self.is_loading = False
        self.loading_dots = 0

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

        # Configure styles before creating notebook
        self.style = ttk.Style()
        self.style.theme_use('default')  # Use default theme as base
        
        # Configure notebook style for dark mode
        self.style.configure("Custom.TNotebook",
                           background="#2E2E2E",
                           foreground="white",
                           padding=5)
        
        # Configure tab style for dark mode
        self.style.configure("Custom.TNotebook.Tab",
                           background="#1E1E1E",
                           foreground="#FFFFFF",
                           padding=[20, 10],
                           font=('Helvetica', 10, 'bold'))
        
        # Map states for the tabs in dark mode
        self.style.map("Custom.TNotebook.Tab",
                      background=[("selected", "#007BFF"),
                                ("active", "#0056b3"),
                                ("!selected", "#1E1E1E")],
                      foreground=[("selected", "#FFFFFF"),
                                ("active", "#FFFFFF"),
                                ("!selected", "#FFFFFF")])

        # Create notebook with custom style
        self.notebook = ttk.Notebook(root, style="Custom.TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Set dark mode as default
        self.is_dark_mode = True  # Initialize in dark mode

        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, 
                                 bg="#2E2E2E", fg="white")  # Dark mode status bar
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Add protocol-specific counters and times
        self.protocol_times = {
            'TCP': deque(maxlen=3600),  # Store up to 1 hour of data (1 point per second)
            'UDP': deque(maxlen=3600),
            'ICMP': deque(maxlen=3600),
            'ARP': deque(maxlen=3600),
            'DNS': deque(maxlen=3600),
            'All': deque(maxlen=3600)
        }
        self.protocol_counts = {
            'TCP': deque(maxlen=3600),
            'UDP': deque(maxlen=3600),
            'ICMP': deque(maxlen=3600),
            'ARP': deque(maxlen=3600),
            'DNS': deque(maxlen=3600),
            'All': deque(maxlen=3600)
        }
        self.protocol_current_count = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'DNS': 0,
            'All': 0
        }

        # Initialize graph data
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.update_interval = 1.0  # Update every second

        # Create tabs with dark mode by default
        self.create_tabs()

        self.is_updating_graph = False  # Initialize the flag

        # Add loading state variable
        self.is_loading = False
        self.loading_dots = 0

    def configure_styles(self):
        """Configure custom styles for the application with dark mode as default."""
        self.style = ttk.Style()
        
        # Configure main theme for dark mode
        self.style.configure("TNotebook",
                           background="#2E2E2E",
                           foreground="white",
                           padding=5)
        
        # Configure tab style with dark theme
        self.style.configure("TNotebook.Tab",
                           background="#1E1E1E",
                           foreground="#FFFFFF",
                           padding=[20, 10],
                           font=('Helvetica', 10, 'bold'))
        
        # Map different states for the tabs
        self.style.map("TNotebook.Tab",
                      background=[("selected", "#007BFF"),
                                ("active", "#0056b3")],
                      foreground=[("selected", "#FFFFFF"),
                                ("active", "#FFFFFF")],
                      expand=[("selected", [1, 1, 1, 0])])
        
        # Frame styles for dark mode
        self.style.configure("Custom.TFrame",
                           background="#2E2E2E",
                           relief="raised",
                           borderwidth=2)
        
        # Button styles with dark theme
        self.style.configure("Blue.TButton",
                           background="#007BFF",
                           foreground="white",
                           padding=[20, 10],
                           font=('Helvetica', 10))
        
        self.style.configure("Red.TButton",
                           background="#dc3545",
                           foreground="white",
                           padding=[20, 10],
                           font=('Helvetica', 10))
        
        self.style.configure("Green.TButton",
                           background="#28a745",
                           foreground="white",
                           padding=[20, 10],
                           font=('Helvetica', 10))
        
        # Label styles for dark mode
        self.style.configure("Custom.TLabel",
                           background="#2E2E2E",
                           foreground="white",
                           font=('Helvetica', 10))
        
        # Entry styles for dark mode
        self.style.configure("Custom.TEntry",
                           fieldbackground="#3E3E3E",
                           foreground="white",
                           insertcolor="white",
                           padding=5)

        # Configure dark mode for all standard ttk widgets
        for widget in ['TFrame', 'TLabel', 'TButton', 'TEntry', 'TCombobox']:
            self.style.configure(widget,
                               background="#2E2E2E",
                               foreground="white",
                               fieldbackground="#3E3E3E",
                               selectbackground="#007BFF",
                               selectforeground="white")

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
        
        # Initialize log file path
        self.log_file = "packet_log.json"
        
        # Create empty log file if it doesn't exist
        if not os.path.exists(self.log_file):
            try:
                with open(self.log_file, "w", encoding='utf-8') as f:
                    f.write("")  # Create empty file
            except Exception as e:
                logging.error(f"Error creating log file: {e}")
        
        # Time series data
        self.packet_times = []
        self.packet_counts = []
        self.bytes_counts = []
        
        # Protocol-specific data
        self.protocol_times = {
            'TCP': deque(maxlen=3600),
            'UDP': deque(maxlen=3600),
            'ICMP': deque(maxlen=3600),
            'ARP': deque(maxlen=3600),
            'DNS': deque(maxlen=3600),
            'All': deque(maxlen=3600)
        }
        self.protocol_counts = {
            'TCP': deque(maxlen=3600),
            'UDP': deque(maxlen=3600),
            'ICMP': deque(maxlen=3600),
            'ARP': deque(maxlen=3600),
            'DNS': deque(maxlen=3600),
            'All': deque(maxlen=3600)
        }
        self.protocol_current_count = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'ARP': 0,
            'DNS': 0,
            'All': 0
        }
        
        # Dark mode tracking
        self.is_dark_mode = True  # Initialize in dark mode
        self.is_updating_graph = False

    def create_tabs(self):
        """Create the tabs for the application."""
        # Create frames with custom style
        self.packet_filter_tab = ttk.Frame(self.notebook, style="Custom.TFrame")
        self.logging_tab = ttk.Frame(self.notebook, style="Custom.TFrame")
        self.inspection_tab = ttk.Frame(self.notebook, style="Custom.TFrame")
        self.statistics_tab = ttk.Frame(self.notebook, style="Custom.TFrame")
        self.about_tab = ttk.Frame(self.notebook, style="Custom.TFrame")  # New About tab

        # Add tabs with custom style
        self.notebook.add(self.packet_filter_tab, text="Packet Filtering")
        self.notebook.add(self.logging_tab, text="Packet Logging")
        self.notebook.add(self.inspection_tab, text="Deep Packet Inspection")
        self.notebook.add(self.statistics_tab, text="Live Statistics")
        self.notebook.add(self.about_tab, text="About")  # Add About tab

        # Configure frame styles
        for frame in [self.packet_filter_tab, self.logging_tab, 
                     self.inspection_tab, self.statistics_tab, self.about_tab]:
            frame.configure(style="Custom.TFrame")

        # Create frames for different sections
        self.packet_filter_frame = ttk.Frame(self.packet_filter_tab, style="Custom.TFrame")
        self.logging_frame = ttk.Frame(self.logging_tab, style="Custom.TFrame")
        self.inspection_frame = ttk.Frame(self.inspection_tab, style="Custom.TFrame")
        self.statistics_frame = ttk.Frame(self.statistics_tab, style="Custom.TFrame")
        self.about_frame = ttk.Frame(self.about_tab, style="Custom.TFrame")

        # Pack frames with padding
        self.packet_filter_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.logging_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.inspection_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.statistics_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.about_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Create tab contents
        self.create_packet_filter_tab()
        self.create_logging_tab()
        self.create_inspection_tab()
        self.create_statistics_tab()
        self.create_about_tab()  # Create About tab content

        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def create_about_tab(self):
        """Create the content for the About tab."""
        # Create main container frame with custom style
        about_container = ttk.Frame(self.about_frame, style="Custom.TFrame")
        about_container.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

        # Title
        title_frame = ttk.Frame(about_container, style="Custom.TFrame")
        title_frame.pack(fill=tk.X, pady=(0, 20))

        title_label = tk.Label(
            title_frame,
            text="SniffWork v1.0",
            font=('Helvetica', 24, 'bold'),
            bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
            fg="white" if self.is_dark_mode else "black"
        )
        title_label.pack(pady=(0, 5))

        subtitle_label = tk.Label(
            title_frame,
            text="Advanced Network Packet Analyzer",
            font=('Helvetica', 14),
            bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
            fg="#00ff00" if self.is_dark_mode else "#008000"
        )
        subtitle_label.pack()

        # Developer Credit
        developer_frame = ttk.Frame(about_container, style="Custom.TFrame")
        developer_frame.pack(fill=tk.X, pady=(0, 20))

        developer_label = tk.Label(
            developer_frame,
            text="Developed by: DevCraftXCoder",
            font=('Helvetica', 12, 'bold'),
            bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
            fg="#007BFF"
        )
        developer_label.pack()

        # Description Text
        desc_frame = ttk.Frame(about_container, style="Custom.TFrame")
        desc_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))

        description_text = scrolledtext.ScrolledText(
            desc_frame,
            wrap=tk.WORD,
            font=('Helvetica', 11),
            bg="#1E1E1E" if self.is_dark_mode else "#FFFFFF",
            fg="white" if self.is_dark_mode else "black",
            relief="flat",
            padx=10,
            pady=10,
            height=15
        )
        description_text.pack(fill=tk.BOTH, expand=True)

        # Program description
        about_text = """
SniffWork is a powerful and user-friendly network packet analyzer designed for real-time network monitoring and analysis. 

Key Features:
• Real-time Packet Capture: Monitor network traffic in real-time with support for multiple protocols
• Protocol Filtering: Filter packets by protocol (TCP, UDP, ICMP, ARP, DNS)
• Deep Packet Inspection: Analyze detailed packet information including headers and payloads
• Live Statistics: View real-time graphs and statistics of network traffic
• Packet Logging: Save captured packets for later analysis
• Dark/Light Mode: Customizable interface theme for comfortable viewing

Supported Protocols:
• TCP (Transmission Control Protocol)
• UDP (User Datagram Protocol)
• ICMP (Internet Control Message Protocol)
• ARP (Address Resolution Protocol)
• DNS (Domain Name System)

Security Features:
• Packet integrity verification
• Protocol anomaly detection
• Traffic pattern analysis
• Detailed logging capabilities

Usage:
1. Start packet capture using the "Start Sniffing" button
2. Select desired protocol filter from the dropdown menu
3. View real-time packet information and statistics
4. Use the logging feature to save captured packets
5. Analyze packet details in the inspection tab
6. Monitor traffic patterns in the statistics tab

Note: Administrative privileges are required for packet capture functionality.

This tool is designed for network administrators, security professionals, and anyone interested in understanding network traffic patterns and behavior.

© 2024 DevCraftXCoder. All rights reserved.
"""
        description_text.insert(tk.END, about_text)
        description_text.config(state='disabled')

        # Version Info
        version_frame = ttk.Frame(about_container, style="Custom.TFrame")
        version_frame.pack(fill=tk.X, pady=(0, 10))

        version_label = tk.Label(
            version_frame,
            text="Version 1.0 | Build 2024.03",
            font=('Helvetica', 10),
            bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
            fg="#888888"
        )
        version_label.pack(side=tk.LEFT)

        # GitHub Link (if applicable)
        github_label = tk.Label(
            version_frame,
            text="GitHub: DevCraftXCoder",
            font=('Helvetica', 10),
            bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
            fg="#007BFF",
            cursor="hand2"
        )
        github_label.pack(side=tk.RIGHT)
        github_label.bind("<Button-1>", lambda e: self.open_github())

    def open_github(self):
        """Open GitHub profile in default browser."""
        import webbrowser
        webbrowser.open("https://github.com/DevCraftXCoder")

    def on_tab_change(self, event):
        """Handle tab change events."""
        selected_tab = self.notebook.tab(self.notebook.select(), "text")
        logging.info(f"Switched to tab: {selected_tab}")
        # You can add logic here to update the content of the tab if needed

    def create_packet_filter_tab(self):
        """Create the content for the Packet Filtering tab with enhanced styling."""
        # Create main container frame with custom style
        self.packet_filter_frame = ttk.Frame(self.packet_filter_tab, style="Custom.TFrame")
        self.packet_filter_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Header frame
        header_frame = ttk.Frame(self.packet_filter_frame, style="Custom.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        header_label = ttk.Label(header_frame,
                               text="Network Packet Capture",
                               font=('Helvetica', 16, 'bold'),
                               foreground="white",
                               background="#2E2E2E")
        header_label.pack(pady=10)

        # Main output text area with enhanced styling
        text_frame = ttk.Frame(self.packet_filter_frame, style="Custom.TFrame")
        text_frame.pack(expand=True, fill=tk.BOTH)
        
        self.output_text = scrolledtext.ScrolledText(
            text_frame,
            width=80,
            height=25,
            bg="#1E1E1E",
            fg="#FFFFFF",
            font=("Consolas", 11),
            insertbackground="white",
            selectbackground="#0056b3",
            selectforeground="white",
            padx=10,
            pady=10
        )
        self.output_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.output_text.config(state='disabled')

        # Control panel with modern styling
        control_panel = ttk.Frame(self.packet_filter_frame, style="Custom.TFrame")
        control_panel.pack(fill=tk.X, padx=10, pady=5)

        # Status frame with gradient-like effect
        status_frame = ttk.Frame(control_panel, style="Custom.TFrame")
        status_frame.pack(fill=tk.X, pady=5)

        self.packet_count_label = tk.Label(
            status_frame,
            text="Packets Captured: 0",
            font=('Helvetica', 12, 'bold'),
            bg="#2E2E2E",
            fg="#00ff00"
        )
        self.packet_count_label.pack(side=tk.LEFT, padx=10)

        # Protocol selector with custom styling
        protocol_frame = ttk.Frame(control_panel, style="Custom.TFrame")
        protocol_frame.pack(fill=tk.X, pady=5)

        protocol_label = ttk.Label(
            protocol_frame,
            text="Protocol Filter:",
            font=('Helvetica', 10),
            foreground="white",
            background="#2E2E2E"
        )
        protocol_label.pack(side=tk.LEFT, padx=5)

        self.protocol_var = tk.StringVar(value="All")
        protocol_options = ["All", "TCP", "UDP", "ICMP", "ARP", "DNS"]
        protocol_menu = ttk.OptionMenu(
            protocol_frame,
            self.protocol_var,
            *protocol_options
        )
        protocol_menu.pack(side=tk.LEFT, padx=5)

        # IP Entry with modern styling
        ip_frame = ttk.Frame(control_panel, style="Custom.TFrame")
        ip_frame.pack(fill=tk.X, pady=5)

        self.ip_entry = tk.Entry(
            ip_frame,
            width=20,
            font=("Helvetica", 11),
            bg="#3E3E3E",
            fg="white",
            insertbackground="white",
            relief="flat"
        )
        self.ip_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.ip_entry.insert(0, "Enter IP Address")
        self.ip_entry.bind("<FocusIn>", self.on_entry_click)
        self.ip_entry.bind("<FocusOut>", self.on_focus_out)

        # Button container with modern styling
        button_container = ttk.Frame(self.packet_filter_frame, style="Custom.TFrame")
        button_container.pack(fill=tk.X, padx=10, pady=10)

        # Action buttons with enhanced styling
        start_button = tk.Button(
            button_container,
            text="▶ Start Sniffing",
            command=self.start_sniffing_thread,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        start_button.pack(side=tk.LEFT, padx=5)

        stop_button = tk.Button(
            button_container,
            text="⬛ Stop Sniffing",
            command=self.stop_sniffing,
            bg="#dc3545",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        stop_button.pack(side=tk.LEFT, padx=5)

        ping_button = tk.Button(
            button_container,
            text="📡 Ping",
            command=self.ping,
            bg="#007BFF",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        ping_button.pack(side=tk.LEFT, padx=5)

        clear_button = tk.Button(
            button_container,
            text="🗑 Clear Output",
            command=self.clear_output,
            bg="#6c757d",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        clear_button.pack(side=tk.LEFT, padx=5)

        # Add hover effects for buttons
        for button in [start_button, stop_button, ping_button, clear_button]:
            button.bind("<Enter>", lambda e, b=button: self.on_button_hover(e, b))
            button.bind("<Leave>", lambda e, b=button: self.on_button_leave(e, b))

    def on_button_hover(self, event, button):
        """Handle button hover effect."""
        original_color = button.cget("background")
        # Darken the color for hover effect
        r = int(int(original_color[1:3], 16) * 0.8)
        g = int(int(original_color[3:5], 16) * 0.8)
        b = int(int(original_color[5:7], 16) * 0.8)
        button.configure(background=f"#{r:02x}{g:02x}{b:02x}")

    def on_button_leave(self, event, button):
        """Handle button leave effect."""
        # Restore original color
        if "Start" in button.cget("text"):
            button.configure(background="#28a745")
        elif "Stop" in button.cget("text"):
            button.configure(background="#dc3545")
        elif "Ping" in button.cget("text"):
            button.configure(background="#007BFF")
        else:
            button.configure(background="#6c757d")

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
        """Create the content for the Packet Logging tab with modern styling."""
        # Create main container frame with custom style
        logging_container = ttk.Frame(self.logging_frame, style="Custom.TFrame")
        logging_container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Header frame
        header_frame = ttk.Frame(logging_container, style="Custom.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        header_label = ttk.Label(header_frame,
                               text="Packet Log Viewer",
                               font=('Helvetica', 16, 'bold'),
                               foreground="white",
                               background="#2E2E2E")
        header_label.pack(pady=10)

        # Text area frame with modern styling
        text_frame = ttk.Frame(logging_container, style="Custom.TFrame")
        text_frame.pack(expand=True, fill=tk.BOTH)

        self.logging_text = scrolledtext.ScrolledText(
            text_frame,
            width=80,
            height=25,
            bg="#1E1E1E",
            fg="#FFFFFF",
            font=("Consolas", 11),
            insertbackground="white",
            selectbackground="#0056b3",
            selectforeground="white",
            padx=10,
            pady=10
        )
        self.logging_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.logging_text.config(state='disabled')

        # Button container with modern styling
        button_container = ttk.Frame(logging_container, style="Custom.TFrame")
        button_container.pack(fill=tk.X, pady=10)

        # Center container for buttons
        center_buttons = ttk.Frame(button_container, style="Custom.TFrame")
        center_buttons.pack(expand=True)

        # View and Update buttons (Blue)
        view_button = tk.Button(
            center_buttons,
            text="📋 View Packet Log",
            command=self.view_packet_log,
            bg="#007BFF",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        view_button.pack(side=tk.LEFT, padx=5)

        update_button = tk.Button(
            center_buttons,
            text="🔄 Update View",
            command=self.update_view_log,
            bg="#007BFF",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        update_button.pack(side=tk.LEFT, padx=5)

        # Export buttons (Green)
        export_json_button = tk.Button(
            center_buttons,
            text="💾 Export JSON",
            command=self.export_packet_log,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        export_json_button.pack(side=tk.LEFT, padx=5)

        export_csv_button = tk.Button(
            center_buttons,
            text="📊 Export CSV",
            command=self.export_to_csv,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        export_csv_button.pack(side=tk.LEFT, padx=5)

        # Clear logs button (Red)
        clear_logs_button = tk.Button(
            center_buttons,
            text="🗑 Clear Log File",
            command=self.clear_packet_logs,
            bg="#dc3545",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        clear_logs_button.pack(side=tk.LEFT, padx=5)

        # Add hover effects for all buttons
        for button in [view_button, update_button, export_json_button, 
                      export_csv_button, clear_logs_button]:
            button.bind("<Enter>", lambda e, b=button: self.on_button_hover(e, b))
            button.bind("<Leave>", lambda e, b=button: self.on_button_leave(e, b))

        # Create pagination frame with modern styling
        self.pagination_frame = ttk.Frame(logging_container, style="Custom.TFrame")
        self.pagination_frame.pack(fill=tk.X, pady=10)

        # Style for pagination controls
        pagination_style = {
            'bg': "#3E3E3E",
            'fg': "white",
            'font': ("Helvetica", 10),
            'relief': "flat",
            'padx': 10,
            'pady': 5,
            'cursor': "hand2"
        }

    def clear_packet_logs(self):
        """Clear the packet log file after confirmation."""
        if messagebox.askyesno("Clear Logs", "Are you sure you want to clear all packet logs? This cannot be undone."):
            try:
                # Get absolute path of the log file
                abs_log_path = os.path.abspath(self.log_file)
                print(f"Clearing log file at: {abs_log_path}")  # Debug print
                
                try:
                    # First try to remove the file completely
                    if os.path.exists(abs_log_path):
                        os.remove(abs_log_path)
                        print("File removed successfully")  # Debug print
                except Exception as e:
                    print(f"Could not remove file: {e}")  # Debug print
                    # If removal fails, try to clear contents
                    with open(abs_log_path, 'w', encoding='utf-8') as f:
                        f.truncate(0)  # Truncate file to 0 bytes
                        f.flush()  # Force write to disk
                        os.fsync(f.fileno())  # Ensure it's written to disk
                
                # Create new empty file
                with open(abs_log_path, 'w', encoding='utf-8') as f:
                    f.write("")  # Create empty file
                    f.flush()
                    os.fsync(f.fileno())
                
                # Clear the display
                self.clear_text(self.logging_text)
                self.insert_text(self.logging_text, "Packet logs cleared successfully.\n")
                
                # Reset pagination
                self.current_page = 0
                if hasattr(self, 'page_label'):
                    self.page_label.config(text="Page 1 of 1")
                if hasattr(self, 'prev_button'):
                    self.prev_button.config(state=tk.DISABLED)
                if hasattr(self, 'next_button'):
                    self.next_button.config(state=tk.DISABLED)
                
                # Clear the packet list in inspection tab
                if hasattr(self, 'packet_listbox'):
                    self.packet_listbox.delete(0, tk.END)
                
                # Update status
                self.status_bar.config(text="Packet logs cleared")
                
                # Force garbage collection
                gc.collect()
                
                # Verify file is empty
                if os.path.exists(abs_log_path):
                    size = os.path.getsize(abs_log_path)
                    if size == 0:
                        print("Verified: File is empty")  # Debug print
                    else:
                        print(f"Warning: File size is {size} bytes")  # Debug print
                
                messagebox.showinfo("Success", "Packet logs have been cleared successfully.")
                
            except PermissionError:
                messagebox.showerror("Error", "Permission denied. Cannot clear log file. Try running the application as administrator.")
                logging.error(f"Permission denied while clearing log file at {abs_log_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear packet logs: {str(e)}")
                logging.error(f"Error clearing packet logs: {e}")
                print(f"Error details: {e}")  # Debug print

    def create_inspection_tab(self):
        """Create the content for the Packet Inspection tab with modern styling."""
        # Create main container frame with custom style
        inspection_container = ttk.Frame(self.inspection_frame, style="Custom.TFrame")
        inspection_container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Header frame
        header_frame = ttk.Frame(inspection_container, style="Custom.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        header_label = ttk.Label(header_frame,
                               text="Packet Inspector",
                               font=('Helvetica', 16, 'bold'),
                               foreground="white",
                               background="#2E2E2E")
        header_label.pack(pady=10)

        # Create left panel for packet list
        left_panel = ttk.Frame(inspection_container, style="Custom.TFrame")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Packet list with modern styling
        self.packet_listbox = tk.Listbox(
            left_panel,
            bg="#1E1E1E",
            fg="#FFFFFF",
            font=("Consolas", 11),
            selectmode=tk.SINGLE,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightcolor="#007BFF",
            selectbackground="#0056b3",
            selectforeground="white"
        )
        self.packet_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for packet list
        list_scrollbar = ttk.Scrollbar(left_panel)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure scrollbar
        self.packet_listbox.config(yscrollcommand=list_scrollbar.set)
        list_scrollbar.config(command=self.packet_listbox.yview)

        # Create right panel for packet details
        right_panel = ttk.Frame(inspection_container, style="Custom.TFrame")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Packet details text area with modern styling
        self.packet_details = scrolledtext.ScrolledText(
            right_panel,
            width=50,
            height=25,
            bg="#1E1E1E",
            fg="#FFFFFF",
            font=("Consolas", 11),
            insertbackground="white",
            selectbackground="#0056b3",
            selectforeground="white",
            padx=10,
            pady=10
        )
        self.packet_details.pack(fill=tk.BOTH, expand=True)
        self.packet_details.config(state='disabled')

        # Button container with modern styling
        button_container = ttk.Frame(inspection_container, style="Custom.TFrame")
        button_container.pack(fill=tk.X, pady=10)

        # Action buttons with modern styling
        refresh_button = tk.Button(
            button_container,
            text="🔄 Refresh List",
            command=self.refresh_packet_list,
            bg="#007BFF",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        refresh_button.pack(side=tk.LEFT, padx=5)

        inspect_button = tk.Button(
            button_container,
            text="🔍 Inspect Packet",
            command=self.inspect_selected_packet,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        inspect_button.pack(side=tk.LEFT, padx=5)

        clear_button = tk.Button(
            button_container,
            text="🗑 Clear Details",
            command=self.clear_packet_details,
            bg="#dc3545",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        clear_button.pack(side=tk.LEFT, padx=5)

        # Add hover effects for buttons
        for button in [refresh_button, inspect_button, clear_button]:
            button.bind("<Enter>", lambda e, b=button: self.on_button_hover(e, b))
            button.bind("<Leave>", lambda e, b=button: self.on_button_leave(e, b))

        # Bind selection event
        self.packet_listbox.bind('<<ListboxSelect>>', self.on_select_packet)

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
                raw_payload = packet[Raw].load.decode('utf-8', errors='replace')
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
        if not self.sniffing:
            self.sniffing = True
            # Show loading indicator
            self.show_loading_indicator()
            # Create and start the sniffing thread
            self.sniff_thread = threading.Thread(target=self.start_sniffing, daemon=True)
            self.sniff_thread.start()

    def show_loading_indicator(self):
        """Show a loading indicator while capture is initializing."""
        if not hasattr(self, 'loading_window'):
            # Create loading window
            self.loading_window = tk.Toplevel(self.root)
            self.loading_window.title("Initializing Capture")
            
            # Make window non-modal and remove grab
            self.loading_window.transient(self.root)
            
            # Remove window decorations and make it stay on top
            self.loading_window.overrideredirect(True)
            self.loading_window.attributes('-topmost', True)
            
            # Calculate position - place it in the top-right corner of the main window
            main_x = self.root.winfo_x()
            main_y = self.root.winfo_y()
            main_width = self.root.winfo_width()
            
            window_width = 200
            window_height = 50
            
            # Position the window in the top-right corner with a small margin
            x = main_x + main_width - window_width - 20
            y = main_y + 20
            
            self.loading_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
            
            # Create a frame with a border effect
            frame = tk.Frame(
                self.loading_window,
                bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
                bd=1,
                relief="solid"
            )
            frame.pack(fill=tk.BOTH, expand=True)
            
            # Add loading message and dots in a horizontal layout
            msg_frame = tk.Frame(
                frame,
                bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0"
            )
            msg_frame.pack(fill=tk.BOTH, expand=True)
            
            self.loading_label = tk.Label(
                msg_frame,
                text="Initializing",
                font=("Helvetica", 10),
                bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
                fg="white" if self.is_dark_mode else "black"
            )
            self.loading_label.pack(side=tk.LEFT, padx=5)
            
            self.dots_label = tk.Label(
                msg_frame,
                text="",
                font=("Helvetica", 10),
                bg="#2E2E2E" if self.is_dark_mode else "#F0F0F0",
                fg="#00ff00" if self.is_dark_mode else "#008000"
            )
            self.dots_label.pack(side=tk.LEFT)
            
            self.is_loading = True
            self.animate_loading()
            
            # Update the window's position when the main window moves
            self.root.bind('<Configure>', self.update_loading_position)

    def animate_loading(self):
        """Animate the loading indicator dots."""
        if self.is_loading:
            dots = "." * (self.loading_dots % 4)
            self.dots_label.config(text=dots)
            self.loading_dots += 1
            self.root.after(500, self.animate_loading)

    def hide_loading_indicator(self):
        """Hide the loading indicator."""
        if hasattr(self, 'loading_window'):
            self.is_loading = False
            self.loading_window.destroy()
            delattr(self, 'loading_window')

    def stop_sniffing(self):
        """Stop the packet sniffing."""
        if self.sniffing:
            self.sniffing = False
            self.clear_terminal()
            print("\n" + "═" * 60)
            print("Packet Capture Stopped")
            print("═" * 60)
            self.update_status("Packet capture stopped")
            self.hide_loading_indicator()

    def packet_callback(self, packet):
        """Process captured packets and update statistics."""
        if not self.sniffing:
            return

        try:
            # Update status on first packet
            if self.packet_count == 0:
                self.status_bar.config(text="Capture active", fg="white")
                self.loading_label.config(text="●", fg="#00ff00")  # Show active indicator
            
            # Create a queue for GUI updates if it doesn't exist
            if not hasattr(self, 'gui_update_queue'):
                self.gui_update_queue = []

            # Get current time
            current_time = time.time()
            
            # Update total bytes and packet sizes
            packet_size = len(packet)
            self.total_bytes += packet_size
            self.packet_sizes.append(packet_size)
            
            # Format packet details for logging
            packet_details = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'protocol': 'Unknown',
                'src': '',
                'dst': '',
                'src_port': '',
                'dst_port': '',
                'length': packet_size,
                'payload': ''
            }
            
            # Determine packet protocol and update counters
            if IP in packet:
                packet_details['src'] = packet[IP].src
                packet_details['dst'] = packet[IP].dst
                
                if TCP in packet:
                    packet_details['protocol'] = 'TCP'
                    packet_details['src_port'] = packet[TCP].sport
                    packet_details['dst_port'] = packet[TCP].dport
                    self.protocol_count['TCP'] += 1
                elif UDP in packet:
                    packet_details['protocol'] = 'UDP'
                    packet_details['src_port'] = packet[UDP].sport
                    packet_details['dst_port'] = packet[UDP].dport
                    self.protocol_count['UDP'] += 1
                elif ICMP in packet:
                    packet_details['protocol'] = 'ICMP'
                    self.protocol_count['ICMP'] += 1
                
                if packet.haslayer(DNS):
                    packet_details['protocol'] = 'DNS'
                    self.protocol_count['DNS'] += 1
            elif ARP in packet:
                packet_details['protocol'] = 'ARP'
                packet_details['src'] = packet[ARP].psrc
                packet_details['dst'] = packet[ARP].pdst
                self.protocol_count['ARP'] += 1

            # Add payload if present
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                    packet_details['payload'] = payload[:500]  # Limit payload size
                except:
                    packet_details['payload'] = packet[Raw].load.hex()[:500]  # Hex format if can't decode

            # Log packet to JSON file
            self.log_packet(packet_details)

            # Update protocol-specific statistics
            if packet_details['protocol'] in self.protocol_times:
                self.protocol_current_count[packet_details['protocol']] += 1
                self.protocol_times[packet_details['protocol']].append(current_time)
                self.protocol_counts[packet_details['protocol']].append(
                    self.protocol_current_count[packet_details['protocol']]
                )

            # Update "All" protocol statistics
            self.protocol_current_count['All'] += 1
            self.protocol_times['All'].append(current_time)
            self.protocol_counts['All'].append(self.protocol_current_count['All'])

            # Store packet for analysis (limit stored packets to prevent memory issues)
            MAX_STORED_PACKETS = 1000
            self.captured_packets.append(packet)
            if len(self.captured_packets) > MAX_STORED_PACKETS:
                self.captured_packets.pop(0)

            # Update packet count
            self.packet_count += 1

            # Format packet info for display
            packet_info = self.format_packet_info(packet)
            
            # Queue GUI updates
            self.gui_update_queue.append(packet_info)
            
            # Process GUI updates periodically
            if len(self.gui_update_queue) >= 10 or (current_time - getattr(self, 'last_gui_update', 0) > 0.5):
                self.process_gui_updates()

        except Exception as e:
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
            # Create the file if it doesn't exist
            if not os.path.exists(self.log_file):
                try:
                    with open(self.log_file, "w", encoding='utf-8') as f:
                        f.write("")  # Create empty file
                except Exception as create_error:
                    logging.error(f"Error creating log file: {create_error}")

    def process_gui_updates(self):
        """Process queued GUI updates."""
        try:
            if not hasattr(self, 'last_gui_update'):
                self.last_gui_update = time.time()
            
            if hasattr(self, 'gui_update_queue') and self.gui_update_queue:
                # Update statistics labels
                self.root.after(0, self.update_statistics_labels)
                
                # Update text display with all queued packets
                combined_info = ''.join(self.gui_update_queue)
                self.root.after(0, lambda: self.insert_text(self.output_text, combined_info))
                
                # Clear the queue
                self.gui_update_queue = []
                self.last_gui_update = time.time()
        except Exception as e:
            logging.error(f"Error processing GUI updates: {e}")

    def format_packet_info(self, packet):
        """Format packet information for display."""
        packet_info = "═" * 60 + "\n"
        packet_info += f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        try:
            # Determine protocol type
            protocol_type = "Unknown"
            if IP in packet:
                if TCP in packet:
                    protocol_type = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    packet_info += f"Protocol: {protocol_type}\n"
                    packet_info += f"Source IP: {packet[IP].src}:{src_port}\n"
                    packet_info += f"Destination IP: {packet[IP].dst}:{dst_port}\n"
                    # Add TCP flags
                    flags = []
                    if packet[TCP].flags.S: flags.append('SYN')
                    if packet[TCP].flags.A: flags.append('ACK')
                    if packet[TCP].flags.F: flags.append('FIN')
                    if packet[TCP].flags.R: flags.append('RST')
                    if packet[TCP].flags.P: flags.append('PSH')
                    packet_info += f"TCP Flags: {' '.join(flags) if flags else 'None'}\n"
                elif UDP in packet:
                    protocol_type = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    packet_info += f"Protocol: {protocol_type}\n"
                    packet_info += f"Source IP: {packet[IP].src}:{src_port}\n"
                    packet_info += f"Destination IP: {packet[IP].dst}:{dst_port}\n"
                elif ICMP in packet:
                    protocol_type = "ICMP"
                    packet_info += f"Protocol: {protocol_type}\n"
                    packet_info += f"Source IP: {packet[IP].src}\n"
                    packet_info += f"Destination IP: {packet[IP].dst}\n"
                    packet_info += f"ICMP Type: {packet[ICMP].type}\n"
                    packet_info += f"ICMP Code: {packet[ICMP].code}\n"
                
                if packet.haslayer(DNS):
                    protocol_type = "DNS"
                    packet_info += "DNS Information:\n"
                    if packet.haslayer(DNSQR):
                        packet_info += f"  Query: {packet[DNSQR].qname.decode()}\n"
                    if packet.haslayer(DNSRR):
                        packet_info += f"  Response: {packet[DNSRR].rdata}\n"
            elif ARP in packet:
                protocol_type = "ARP"
                packet_info += f"Protocol: {protocol_type}\n"
                packet_info += f"Source MAC: {packet[ARP].hwsrc}\n"
                packet_info += f"Destination MAC: {packet[ARP].hwdst}\n"
                packet_info += f"Source IP: {packet[ARP].psrc}\n"
                packet_info += f"Destination IP: {packet[ARP].pdst}\n"
                packet_info += f"Operation: {'Request' if packet[ARP].op == 1 else 'Reply'}\n"
            
            # Add a clear protocol identifier at the top
            packet_info = f"[{protocol_type} Packet]\n" + packet_info
            
            # Add packet length
            packet_info += f"Packet Length: {len(packet)} bytes\n"
            
            # Add payload if present
            if Raw in packet:
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='replace')
                    if len(payload) > 100:
                        packet_info += f"Payload: {payload[:100]}...\n"
                    else:
                        packet_info += f"Payload: {payload}\n"
                except:
                    hex_payload = packet[Raw].load.hex()
                    if len(hex_payload) > 100:
                        packet_info += f"Payload (hex): {hex_payload[:100]}...\n"
                    else:
                        packet_info += f"Payload (hex): {hex_payload}\n"
        except Exception as e:
            packet_info += f"Error formatting packet details: {str(e)}\n"
        
        packet_info += "═" * 60 + "\n\n"
        return packet_info

    def update_statistics_labels(self):
        """Update the statistics labels with current values."""
        try:
            # Update total packets
            self.total_packets_label.config(text=f"Total Packets: {self.packet_count}")
            
            # Update total bytes
            self.total_bytes_label.config(text=f"Total Bytes: {self.total_bytes}")
            
            # Update average packet size
            if self.packet_sizes:
                avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
                self.avg_packet_size_label.config(text=f"Average Packet Size: {avg_size:.2f} bytes")
            
            # Update protocol counts
            for protocol in self.protocol_count:
                if protocol in self.protocol_labels:
                    self.protocol_labels[protocol].config(
                        text=f"{protocol}: {self.protocol_count[protocol]}"
                    )
            
            # Update packet count in main display
            self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
            
        except Exception as e:
            logging.error(f"Error updating statistics labels: {e}")

    def clear_statistics(self):
        """Reset all statistics counters and displays."""
        try:
            # Reset counters
            self.packet_count = 0
            self.total_bytes = 0
            self.packet_sizes = []
            
            # Reset protocol counts
            for protocol in self.protocol_count:
                self.protocol_count[protocol] = 0
                self.protocol_current_count[protocol] = 0
                if protocol in self.protocol_times:
                    self.protocol_times[protocol] = []
                    self.protocol_counts[protocol] = []
            
            # Reset "All" protocol statistics
            self.protocol_current_count['All'] = 0
            self.protocol_times['All'] = []
            self.protocol_counts['All'] = []
            
            # Update labels
            self.update_statistics_labels()
            
            # Clear graph
            self.clear_graph()
            
        except Exception as e:
            logging.error(f"Error clearing statistics: {e}")

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
            try:
                with open(self.log_file, "r", encoding='utf-8') as f:
                    all_lines = [line.strip() for line in f if line.strip()]  # Remove empty lines
            except Exception as e:
                self.insert_text(self.logging_text, f"Error reading log file: {str(e)}\n")
                return
            
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
                    packet_data = json.loads(line)
                    formatted_output = self.format_packet_log_entry(packet_data)
                    self.insert_text(self.logging_text, formatted_output)
                except json.JSONDecodeError as e:
                    logging.error(f"Error parsing JSON: {e}")
                    self.insert_text(self.logging_text, f"Error parsing packet data: {line[:100]}...\n")
                    continue
                except Exception as e:
                    logging.error(f"Error processing log entry: {e}")
                    continue

            # Update or create pagination controls
            self.update_pagination_controls(total_pages)

            # Scroll to top of text widget
            self.logging_text.see("1.0")

        except Exception as e:
            error_msg = f"Error loading packet log: {str(e)}\n"
            self.insert_text(self.logging_text, error_msg)
            logging.error(f"Error loading packet log: {e}")

    def format_packet_log_entry(self, packet_data):
        """Format a packet log entry for display."""
        try:
            output = "╔" + "═" * 58 + "╗\n"
            
            # Timestamp and Protocol
            output += f"║ Time: {packet_data.get('timestamp', 'N/A'):<52}║\n"
            output += f"║ Protocol: {packet_data.get('protocol', 'Unknown'):<49}║\n"
            
            # Source Information
            if packet_data.get('src'):
                src_info = packet_data['src']
                if packet_data.get('src_port'):
                    src_info += f":{packet_data['src_port']}"
                output += f"║ Source: {src_info:<51}║\n"
            
            # Destination Information
            if packet_data.get('dst'):
                dst_info = packet_data['dst']
                if packet_data.get('dst_port'):
                    dst_info += f":{packet_data['dst_port']}"
                output += f"║ Destination: {dst_info:<47}║\n"
            
            # Packet Length
            if packet_data.get('length'):
                output += f"║ Length: {packet_data['length']} bytes{' ' * (44 - len(str(packet_data['length'])))}║\n"
            
            # Payload (if exists)
            payload = packet_data.get('payload', '')
            if payload:
                output += "║ Payload:                                                    ║\n"
                # Split payload into chunks of 50 characters
                payload = payload[:200]  # Limit payload display
                chunks = [payload[i:i+50] for i in range(0, len(payload), 50)]
                for chunk in chunks:
                    output += f"║ {chunk:<58}║\n"
            
            output += "╚" + "═" * 58 + "╝\n\n"
            return output
        except Exception as e:
            logging.error(f"Error formatting packet log entry: {e}")
            return f"Error formatting packet data: {str(e)}\n"

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
        try:
            if not self.is_dark_mode:
                # Switch to dark mode
                self.root.configure(bg="#2E2E2E")
                self.style.configure("TFrame", background="#2E2E2E")
                self.style.configure("Custom.TFrame", background="#2E2E2E")
                
                # Update notebook style
                self.style.configure("TNotebook", background="#2E2E2E")
                self.style.configure("TNotebook.Tab",
                                   background="#1E1E1E",
                                   foreground="#FFFFFF")
                
                # Update all frames
                for tab in [self.packet_filter_tab, self.logging_tab, 
                          self.inspection_tab, self.statistics_tab]:
                    tab.configure(style="Custom.TFrame")
                
                # Update text widgets
                for widget in self.root.winfo_children():
                    if isinstance(widget, scrolledtext.ScrolledText):
                        widget.configure(bg="#1E1E1E", fg="#FFFFFF",
                                      insertbackground="white")
                    elif isinstance(widget, tk.Label):
                        widget.configure(bg="#2E2E2E", fg="white")
                    elif isinstance(widget, tk.Button):
                        widget.configure(bg="#007BFF", fg="white")
                    elif isinstance(widget, ttk.Frame):
                        widget.configure(style="Custom.TFrame")
                
                # Update protocol labels
                if hasattr(self, 'protocol_labels'):
                    for label in self.protocol_labels.values():
                        label.configure(bg="#2E2E2E", fg="white")
                
                # Update statistics labels
                for attr in ['total_packets_label', 'total_bytes_label', 
                           'avg_packet_size_label']:
                    if hasattr(self, attr):
                        getattr(self, attr).configure(bg="#2E2E2E", fg="white")
                
                self.is_dark_mode = True
                logging.info("Switched to dark mode")
                
            else:
                # Switch to light mode
                self.root.configure(bg="#F0F0F0")  # Light gray background
                self.style.configure("TFrame", background="#F0F0F0")
                self.style.configure("Custom.TFrame", background="#F0F0F0")
                
                # Update notebook style
                self.style.configure("TNotebook", background="#F0F0F0")
                self.style.configure("TNotebook.Tab",
                                   background="#E0E0E0",
                                   foreground="#000000")
                
                # Update all frames
                for tab in [self.packet_filter_tab, self.logging_tab, 
                          self.inspection_tab, self.statistics_tab]:
                    tab.configure(style="Custom.TFrame")
                
                # Update text widgets
                for widget in self.root.winfo_children():
                    if isinstance(widget, scrolledtext.ScrolledText):
                        widget.configure(bg="#FFFFFF", fg="#000000",
                                      insertbackground="black")
                    elif isinstance(widget, tk.Label):
                        widget.configure(bg="#F0F0F0", fg="black")
                    elif isinstance(widget, tk.Button):
                        widget.configure(bg="#E0E0E0", fg="black")
                    elif isinstance(widget, ttk.Frame):
                        widget.configure(style="Custom.TFrame")
                
                # Update protocol labels
                if hasattr(self, 'protocol_labels'):
                    for label in self.protocol_labels.values():
                        label.configure(bg="#F0F0F0", fg="black")
                
                # Update statistics labels
                for attr in ['total_packets_label', 'total_bytes_label', 
                           'avg_packet_size_label']:
                    if hasattr(self, attr):
                        getattr(self, attr).configure(bg="#F0F0F0", fg="black")
                
                self.is_dark_mode = False
                logging.info("Switched to light mode")
            
            # Update graph colors and visibility
            if hasattr(self, 'ax') and hasattr(self, 'canvas'):
                # Set background colors
                self.ax.set_facecolor('#1E1E1E' if self.is_dark_mode else '#FFFFFF')
                self.fig.set_facecolor('#2E2E2E' if self.is_dark_mode else '#F0F0F0')
                
                # Update grid color
                self.ax.grid(color='#555555' if self.is_dark_mode else '#CCCCCC')
                
                # Set text colors
                self.ax.title.set_color('white' if self.is_dark_mode else 'black')
                self.ax.xaxis.label.set_color('white' if self.is_dark_mode else 'black')
                self.ax.yaxis.label.set_color('white' if self.is_dark_mode else 'black')
                
                # Set tick colors
                for label in self.ax.get_xticklabels():
                    label.set_color('white' if self.is_dark_mode else 'black')
                for label in self.ax.get_yticklabels():
                    label.set_color('white' if self.is_dark_mode else 'black')
                    
                # Update spines
                for spine in self.ax.spines.values():
                    spine.set_edgecolor('white' if self.is_dark_mode else 'black')
                
                # Force redraw
                self.canvas.draw()
            
        except Exception as e:
            logging.error(f"Error toggling dark mode: {e}")
            messagebox.showerror("Error", f"Failed to toggle dark mode: {str(e)}")

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
        """Export the captured packets to a CSV file."""
        if not self.captured_packets:
            messagebox.showinfo("No Data", "No packets captured yet. Start sniffing to capture packets.")
            return
        
        try:
            # Ask user for filename
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Save Packet Data as CSV"
            )
            
            if not filename:  # User cancelled
                return
                
            # Write to CSV
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
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
                    'Payload'
                ])
                
                # Write data rows
                for packet in self.captured_packets:
                    row = self._format_packet_for_csv(packet)
                    writer.writerow(row)
            
            messagebox.showinfo("Export Complete", f"Successfully exported {len(self.captured_packets)} packets to {filename}")
            self.update_status(f"Exported {len(self.captured_packets)} packets to CSV")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
            logging.error(f"CSV export error: {e}")

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
        """Create the content for the Statistics tab with modern styling."""
        # Create main container frame with custom style
        stats_container = ttk.Frame(self.statistics_frame, style="Custom.TFrame")
        stats_container.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Header frame
        header_frame = ttk.Frame(stats_container, style="Custom.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=5)

        header_label = ttk.Label(header_frame,
                               text="Network Statistics",
                               font=('Helvetica', 16, 'bold'),
                               foreground="white",
                               background="#2E2E2E")
        header_label.pack(pady=10)

        # Create left panel for statistics
        left_panel = ttk.Frame(stats_container, style="Custom.TFrame")
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # Statistics labels with modern styling
        stats_style = {
            'font': ('Helvetica', 12),
            'bg': "#2E2E2E",
            'fg': "white",
            'pady': 5
        }

        # Total packets
        self.total_packets_label = tk.Label(
            left_panel,
            text="Total Packets: 0",
            **stats_style
        )
        self.total_packets_label.pack(anchor=tk.W)

        # Total bytes
        self.total_bytes_label = tk.Label(
            left_panel,
            text="Total Bytes: 0",
            **stats_style
        )
        self.total_bytes_label.pack(anchor=tk.W)

        # Average packet size
        self.avg_packet_size_label = tk.Label(
            left_panel,
            text="Average Packet Size: 0 bytes",
            **stats_style
        )
        self.avg_packet_size_label.pack(anchor=tk.W)

        # Protocol counts
        protocols_frame = ttk.Frame(left_panel, style="Custom.TFrame")
        protocols_frame.pack(fill=tk.X, pady=10)

        protocols_label = tk.Label(
            protocols_frame,
            text="Protocol Distribution",
            font=('Helvetica', 14, 'bold'),
            bg="#2E2E2E",
            fg="#00ff00"
        )
        protocols_label.pack(anchor=tk.W)

        # Protocol count labels
        self.protocol_labels = {}
        for protocol in ['TCP', 'UDP', 'ICMP', 'ARP', 'DNS']:
            self.protocol_labels[protocol] = tk.Label(
                protocols_frame,
                text=f"{protocol}: 0",
                **stats_style
            )
            self.protocol_labels[protocol].pack(anchor=tk.W)

        # Create right panel for graph
        right_panel = ttk.Frame(stats_container, style="Custom.TFrame")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        # Graph frame
        graph_frame = ttk.Frame(right_panel, style="Custom.TFrame")
        graph_frame.pack(fill=tk.BOTH, expand=True)

        # Create Figure and Canvas for the graph with increased DPI and size
        self.fig = Figure(figsize=(8, 6), dpi=100, facecolor='#2E2E2E')
        self.ax = self.fig.add_subplot(111)
        
        # Style the graph
        self.ax.set_facecolor('#1E1E1E')
        self.ax.tick_params(colors='white', labelsize=8)
        for spine in self.ax.spines.values():
            spine.set_color('white')
        
        # Initialize with proper limits and styling
        self.ax.set_title('Packet Rate Over Time', color='white', pad=20, fontsize=10)
        self.ax.set_xlabel('Time (s)', color='white', fontsize=8)
        self.ax.set_ylabel('Packets/s', color='white', fontsize=8)
        self.ax.grid(True, linestyle='--', alpha=0.3, color='white')
        
        # Set initial axis limits
        self.ax.set_xlim(0, 30)
        self.ax.set_ylim(0, 10)

        # Create canvas with improved rendering
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Button container
        button_container = ttk.Frame(right_panel, style="Custom.TFrame")
        button_container.pack(fill=tk.X, pady=10)

        # Clear graph button with modern styling
        clear_graph_button = tk.Button(
            button_container,
            text="🗑 Clear Graph",
            command=self.clear_graph,
            bg="#dc3545",
            fg="white",
            font=("Helvetica", 11, "bold"),
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        clear_graph_button.pack(side=tk.RIGHT, padx=5)

        # Add hover effect for the clear button
        clear_graph_button.bind("<Enter>", lambda e, b=clear_graph_button: self.on_button_hover(e, b))
        clear_graph_button.bind("<Leave>", lambda e, b=clear_graph_button: self.on_button_leave(e, b))

        # Initialize graph data
        self.packet_times = []
        self.packet_counts = []
        self.last_update_time = time.time()
        self.update_interval = 1.0  # Update every second while sniffing

        # Start the graph update loop immediately
        self.update_graph()

    def update_graph(self):
        """Update the live graph with the latest statistics."""
        try:
            if not hasattr(self, 'ax') or not hasattr(self, 'canvas'):
                return

            # Clear the axes for new data
            self.ax.clear()

            # Get the selected protocol (default to 'All' if not set)
            selected_protocol = getattr(self, 'protocol_var', tk.StringVar(value='All')).get()
            
            # Get the data for plotting
            times = list(self.protocol_times.get(selected_protocol, []))
            counts = list(self.protocol_counts.get(selected_protocol, []))
            
            # Set colors based on current theme
            bg_color = '#1E1E1E' if self.is_dark_mode else '#FFFFFF'
            text_color = '#FFFFFF' if self.is_dark_mode else '#000000'
            grid_color = '#FFFFFF' if self.is_dark_mode else '#808080'
            line_color = '#00ff00' if self.is_dark_mode else '#008000'
            
            # Set background colors
            self.ax.set_facecolor(bg_color)
            self.fig.set_facecolor('#2E2E2E' if self.is_dark_mode else '#F0F0F0')
            
            if times and counts:
                # Convert times to relative times (seconds since start)
                relative_times = [t - self.start_time for t in times]
                
                # Ensure we have a point at x=0 if this is the start
                if not relative_times or relative_times[0] > 0:
                    relative_times.insert(0, 0)
                    counts.insert(0, 0)
                
                # Plot packet counts with improved line style
                self.ax.plot(relative_times, counts, 
                           color=line_color,
                           linewidth=2,
                           marker='.',
                           markersize=4,
                           label=selected_protocol)

                # Dynamic axis limits
                current_time = relative_times[-1]
                x_min = max(0, current_time - 30)  # Show last 30 seconds
                x_max = current_time + 2  # Add 2 second buffer
                
                # Dynamic y-axis limit with minimum of 10
                y_max = max(max(counts) * 1.2, 10)  # At least show up to 10
                
                self.ax.set_xlim(x_min, x_max)
                self.ax.set_ylim(0, y_max)
            else:
                # Default limits if no data
                self.ax.set_xlim(0, 30)
                self.ax.set_ylim(0, 10)

            # Style the graph
            self.ax.grid(True, linestyle='--', alpha=0.3, color=grid_color)
            
            # Set title and labels with proper colors
            self.ax.set_title(f"{selected_protocol} Packets/Second", 
                            color=text_color, 
                            pad=10,
                            fontsize=10)
            self.ax.set_xlabel("Time (seconds)", color=text_color, fontsize=8)
            self.ax.set_ylabel("Packets/sec", color=text_color, fontsize=8)
            
            # Style ticks and spines
            self.ax.tick_params(axis='both', colors=text_color, labelcolor=text_color, labelsize=8)
            for spine in self.ax.spines.values():
                spine.set_color(text_color)

            # Update the canvas with improved rendering
            self.fig.tight_layout()
            self.canvas.draw()

        except Exception as e:
            logging.error(f"Error updating graph: {e}")
        finally:
            # Schedule next update based on sniffing state
            update_interval = 1000 if self.sniffing else 2000  # 1 second when sniffing, 2 seconds when not
            self.root.after(update_interval, self.update_graph)

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

    def refresh_packet_list(self):
        """Refresh the packet list in the inspection tab."""
        try:
            # Clear the current list
            self.packet_listbox.delete(0, tk.END)
            
            # Check if log file exists
            if not os.path.exists(self.log_file):
                self.insert_text(self.packet_details, "No packet log found. Start capturing packets to create a log.\n")
                return
                
            # Read and display packets from the log file
            with open(self.log_file, "r", encoding='utf-8') as f:
                for line in f:
                    try:
                        packet_data = json.loads(line.strip())
                        # Create a summary string for the listbox
                        summary = f"{packet_data['timestamp']} - {packet_data['protocol']}"
                        if packet_data['src']:
                            summary += f" from {packet_data['src']}"
                        if packet_data['dst']:
                            summary += f" to {packet_data['dst']}"
                        self.packet_listbox.insert(tk.END, summary)
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logging.error(f"Error processing packet entry: {e}")
                        continue
            
            # Select the first item if available
            if self.packet_listbox.size() > 0:
                self.packet_listbox.selection_set(0)
                self.inspect_selected_packet()
                
        except Exception as e:
            error_msg = f"Error refreshing packet list: {str(e)}\n"
            self.insert_text(self.packet_details, error_msg)
            logging.error(f"Error refreshing packet list: {e}")

    def inspect_selected_packet(self):
        """Display detailed information about the selected packet."""
        try:
            # Get selected index
            selection = self.packet_listbox.curselection()
            if not selection:
                return
                
            # Clear current details
            self.clear_text(self.packet_details)
            
            # Get the selected packet index
            index = selection[0]
            
            # Read the corresponding packet from the log file
            with open(self.log_file, "r", encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i == index:
                        try:
                            packet_data = json.loads(line.strip())
                            # Format and display packet details
                            details = self.format_packet_details(packet_data)
                            self.insert_text(self.packet_details, details)
                            break
                        except json.JSONDecodeError:
                            self.insert_text(self.packet_details, "Error: Invalid packet data format\n")
                        except Exception as e:
                            self.insert_text(self.packet_details, f"Error processing packet: {str(e)}\n")
                            
        except Exception as e:
            error_msg = f"Error inspecting packet: {str(e)}\n"
            self.insert_text(self.packet_details, error_msg)
            logging.error(f"Error inspecting packet: {e}")

    def format_packet_details(self, packet_data):
        """Format packet details for display."""
        details = "╔═══════════ Packet Details ═══════════╗\n\n"
        
        # Add timestamp
        details += f"Timestamp: {packet_data.get('timestamp', 'N/A')}\n"
        details += "═" * 40 + "\n\n"
        
        # Protocol information
        details += f"Protocol: {packet_data.get('protocol', 'Unknown')}\n"
        details += "═" * 40 + "\n\n"
        
        # Network information
        details += "Network Information:\n"
        details += "─" * 20 + "\n"
        if packet_data.get('src'):
            details += f"Source: {packet_data['src']}\n"
        if packet_data.get('dst'):
            details += f"Destination: {packet_data['dst']}\n"
        if packet_data.get('src_port'):
            details += f"Source Port: {packet_data['src_port']}\n"
        if packet_data.get('dst_port'):
            details += f"Destination Port: {packet_data['dst_port']}\n"
        details += "\n"
        
        # Packet size
        details += f"Packet Length: {packet_data.get('length', 'N/A')} bytes\n"
        details += "═" * 40 + "\n\n"
        
        # Payload information
        details += "Payload:\n"
        details += "─" * 20 + "\n"
        payload = packet_data.get('payload', 'No payload')
        if payload != 'No payload':
            # Limit payload display and add ellipsis if too long
            max_length = 500
            if len(payload) > max_length:
                payload = payload[:max_length] + "...(truncated)"
            details += payload + "\n"
        else:
            details += "No payload\n"
            
        details += "\n╚" + "═" * 38 + "╝\n"
        return details

    def clear_packet_details(self):
        """Clear the packet details display."""
        try:
            self.clear_text(self.packet_details)
            self.packet_listbox.selection_clear(0, tk.END)
            self.insert_text(self.packet_details, "Packet details cleared.\n")
        except Exception as e:
            logging.error(f"Error clearing packet details: {e}")

    def on_select_packet(self, event):
        """Handle packet selection event."""
        self.inspect_selected_packet()

    def start_sniffing(self):
        """Start capturing packets."""
        try:
            self.clear_terminal()
            self.print_capture_banner()
            
            self.start_time = time.time()
            
            # Check for admin privileges
            if platform.system() == 'Windows':
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    print("\n[ERROR] Administrative privileges required!")
                    print("Please run the application as administrator.\n")
                    messagebox.showerror("Permission Error", "This application requires administrative privileges. Please run as administrator.")
                    self.sniffing = False
                    self.hide_loading_indicator()
                    return
            else:
                if not os.geteuid() == 0:
                    print("\n[ERROR] Root privileges required!")
                    print("Please run the application with sudo.\n")
                    messagebox.showerror("Permission Error", "This application requires administrative privileges.")
                    self.sniffing = False
                    self.hide_loading_indicator()
                    return
            
            # Get current filter type
            current_filter = self.protocol_var.get()
            filter_string = self.get_filter_string()
            
            # Display filter information
            filter_info = f"\n[INFO] Starting packet capture with filter: {current_filter}\n"
            if filter_string:
                filter_info += f"[INFO] Filter expression: {filter_string}\n"
            else:
                filter_info += "[INFO] Capturing all packets (no filter)\n"
            
            print(filter_info)
            self.root.after(0, lambda: self.insert_text(self.output_text, filter_info))
            print("[INFO] Press Ctrl+C in the GUI to stop capturing.\n")
            
            # Start packet capture with a timeout to allow checking sniffing flag
            while self.sniffing:
                sniff(prn=self.packet_callback, store=False, filter=filter_string, timeout=0.1)
                
        except Exception as e:
            error_msg = f"\n[ERROR] Failed to start packet capture: {str(e)}"
            print(error_msg)
            logging.error(f"Error starting packet capture: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to start packet capture: {str(e)}"))
            self.sniffing = False
            self.hide_loading_indicator()

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
        if not self.sniffing:
            return
            
        try:
            # Update packet count label
            self.packet_count_label.config(text=f"Packets Captured: {self.packet_count}")
            
            # Update protocol labels if they exist
            if hasattr(self, 'protocol_labels'):
                for protocol in self.protocol_count:
                    if protocol in self.protocol_labels:
                        self.protocol_labels[protocol].config(
                            text=f"{protocol}: {self.protocol_count[protocol]}"
                        )
            
        except Exception as e:
            logging.error(f"Error updating GUI: {e}")
        finally:
            # Schedule next update if still sniffing
            if self.sniffing:
                self.root.after(1000, self.update_gui)  # Update every second

    def update_statistics(self):
        """Update packet statistics."""
        try:
            if self.packet_sizes:
                avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
                self.avg_packet_size_label.config(text=f"Average Packet Size: {avg_size:.2f} bytes")
                
                # Update total bytes
                self.total_bytes_label.config(text=f"Total Bytes: {self.total_bytes}")
                
                # Update total packets
                self.total_packets_label.config(text=f"Total Packets: {self.packet_count}")
                
        except Exception as e:
            logging.error(f"Error updating statistics: {e}")

    def update_loading_position(self, event=None):
        """Update the loading window position when the main window moves."""
        if hasattr(self, 'loading_window') and self.loading_window.winfo_exists():
            # Get main window position and size
            main_x = self.root.winfo_x()
            main_y = self.root.winfo_y()
            main_width = self.root.winfo_width()
            
            # Get loading window size
            window_width = self.loading_window.winfo_width()
            
            # Calculate new position
            x = main_x + main_width - window_width - 20
            y = main_y + 20
            
            # Update loading window position
            self.loading_window.geometry(f"+{x}+{y}")

if __name__ == "__main__":
    # Clear terminal at startup
    if platform.system().lower() == "windows":
        os.system('cls')
    else:
        os.system('clear')
        
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

