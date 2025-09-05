🔍 Penetration Testing Tool  

A simple **GUI-based penetration testing tool** built with **Python, Tkinter, and Nmap**.  
The tool allows users to perform:  
- **Port Scanning** (1–1024 range by default)  
- **Vulnerability Scanning** using Nmap scripts (`--script=vuln`)  
- **Exploitation (Placeholder)** for future enhancements  

This project demonstrates how automated penetration testing can be integrated into a beginner-friendly graphical interface.  

---

## 🚀 Features  
- User-friendly **Tkinter GUI**  
- **Target input** (IP or domain)  
- **Port Scan** to detect open ports and their states  
- **Vulnerability Scan** using Nmap scripting engine  
- **Placeholder Exploitation Module** for future additions  
- **Threaded Execution** to keep the GUI responsive  

---
⚙️ Requirements  
- Python 3.x  
- Tkinter (usually comes pre-installed with Python)  
- Nmap installed on your system ([Download here](https://nmap.org/download.html))  
- `python-nmap` library  

Install dependencies:  
```bash
pip install python-nmap

▶️ Usage

Clone the repository:

git clone https://github.com/yourusername/pentest-tool.git
cd pentest-tool


Make sure Nmap is installed and added to system PATH.

Run the script:

python pentest_tool.py


Enter a target IP or domain in the GUI and click Scan.
