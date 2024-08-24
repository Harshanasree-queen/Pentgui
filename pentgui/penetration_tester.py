import tkinter as tk
from tkinter import scrolledtext
import nmap
import os
import threading

# Add Nmap installation path to the environment PATH
os.environ["PATH"] += os.pathsep + r"C:\Program Files (x86)\Nmap"

class PenTestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Penetration Testing Tool")

        # Input for target
        tk.Label(root, text="Enter Target IP or Domain:").pack()
        self.target_entry = tk.Entry(root)
        self.target_entry.pack()

        # Scan button
        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan)
        self.scan_button.pack()

        # Results text area
        self.results_text = scrolledtext.ScrolledText(root, width=100, height=30)
        self.results_text.pack()

    def start_scan(self):
        target = self.target_entry.get()
        if not target:
            self.results_text.insert(tk.END, "Please enter a target IP address or domain.\n")
            return

        # Run the scan in a separate thread
        threading.Thread(target=self.perform_tests, args=(target,), daemon=True).start()

    def perform_tests(self, target):
        try:
            nm = nmap.PortScanner()

            # Port scan
            self.results_text.insert(tk.END, f"Scanning {target} for open ports...\n")
            nm.scan(target, '1-1024')
            results = f"Port Scan Results for {target}:\n"
            for host in nm.all_hosts():
                results += f"Host: {host}\n"
                for proto in nm[host].all_protocols():
                    results += f"Protocol: {proto}\n"
                    lport = nm[host][proto].keys()
                    for port in lport:
                        results += f"Port: {port}\tState: {nm[host][proto][port]['state']}\n"

            # Vulnerability scan
            self.results_text.insert(tk.END, f"\nRunning vulnerability scan on {target}...\n")
            nm.scan(target, arguments='--script=vuln')
            results += "\nVulnerability Scan Results:\n"
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if 'script' in nm[host][proto][port]:
                            results += f"Port: {port}\n{nm[host][proto][port]['script']}\n"

            # Exploitation (Placeholder)
            results += "\nRunning exploit attempts...\n"
            results += self.run_exploits(target)

            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, results)
        except Exception as e:
            self.results_text.insert(tk.END, f"An error occurred: {e}\n")

    def run_exploits(self, target):
        # Placeholder function for exploitation
        # You can add actual exploitation code here based on vulnerabilities found
        exploit_results = "Exploitation is a sensitive task and should be handled with care.\n"
        # Example exploitation attempt (you'll need to replace this with real exploit code)
        exploit_results += "Attempting a common exploit...\n"
        return exploit_results

def main():
    root = tk.Tk()
    app = PenTestGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
