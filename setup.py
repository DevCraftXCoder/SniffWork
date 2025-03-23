from setuptools import setup, find_packages

setup(
    name="SniffWork",
    version="1.0.0",
    description="Network Packet Analyzer and Monitor",
    author="Jowey",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'matplotlib>=3.5.0',
        'tkinter',
        'pillow',  # For image handling in tkinter
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'sniffwork=Network_Sniffer:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Network Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: System :: Networking :: Monitoring',
        'Topic :: Security',
    ],
    package_data={
        'SniffWork': ['*.ico'],  # Include icon files
    },
    include_package_data=True,
    long_description="""
    SniffWork is a powerful network packet analyzer and monitoring tool built with Python.
    Features:
    - Real-time packet capture and analysis
    - Protocol filtering (TCP, UDP, ICMP, ARP, DNS)
    - Deep packet inspection
    - Live statistics and graphing
    - Packet logging with export capabilities
    - Dark mode support
    - User-friendly GUI interface
    
    Requirements:
    - Windows OS
    - Python 3.8 or higher
    - Administrative privileges for packet capture
    """,
    long_description_content_type="text/markdown",
    keywords='network, packet, sniffer, analyzer, monitoring, security',
) 