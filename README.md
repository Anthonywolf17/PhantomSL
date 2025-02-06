hantom Sleuth (PhantomSL) 🕵️‍♂️
Phantom Sleuth is a network scanning and reconnaissance tool that allows users to gather detailed information about devices on a local network. It offers two scanning modes:

Basic Scan: Retrieves IP, MAC address, hostname, and manufacturer.
Advanced Scan: Performs a full port scan on all discovered hosts.
📌 Features
✅ Basic Scan: Detects devices, retrieves hostnames (if available), and finds MAC manufacturers.
✅ Advanced Scan: Scans all ports on detected hosts using Nmap.
✅ Cross-Platform: Works on Windows and Linux.
✅ Rich Console Interface: Provides a user-friendly command-line interface.

🔧 Installation
1️⃣ Clone the Repository
sh
Copy
git clone https://github.com/yourusername/PhantomSL.git
cd PhantomSL
2️⃣ Install Dependencies
sh
Copy
pip install -r requirements.txt
3️⃣ Install Nmap (For Advanced Scanning)
Windows
Download and install Nmap from nmap.org/download.

Linux
sh
Copy
sudo apt install nmap  # Debian-based
sudo dnf install nmap  # Fedora-based
🚀 Usage
Run the script with:

sh
Copy
python PhantomConsole.py
Menu Options:
1️⃣ Basic Scan – Finds active devices, retrieves IP, MAC, hostname, and manufacturer.
2️⃣ Advanced Scan – Runs a full port scan on detected hosts.

🛠️ Troubleshooting
🔹 If you get missing module errors, run:

sh
Copy
pip install rich requests scapy
🔹 If Nmap scanning fails on Windows, ensure nmap.exe is in your System Path:

Open Command Prompt and type:
sh
Copy
where nmap
If not found, manually add its directory (C:\Program Files (x86)\Nmap) to your System PATH.
📜 License
This project is licensed under the MIT License.

Let me know if you want any edits! 🚀
