import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import nmap
import threading
import time
from colorama import Fore, Style, init

# Initialize colorama
init()

# Function to print text with a delay, "hacker-style"
def delayed_print(text, delay=0.05):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

# Print welcome message in the command prompt with color and delayed writing
delayed_print(Fore.GREEN + "Welcome to Mr-Nmap v2" + Style.RESET_ALL)
delayed_print(Fore.YELLOW + "This script is owned by Winston Ighodaro. Visit me at https://store.cybergeneration.tech" + Style.RESET_ALL)
delayed_print(Fore.YELLOW + "Please ensure you are running this script as root to get the best out of it." + Style.RESET_ALL)


# List of available NSE scripts and flags
nse_scripts = ["vuln", "smtp-commands", "http-title", "ftp-anon", "ssh-brute", "ssl-cert", 
               "http-enum", "http-vuln-cve2017-5638", "mysql-info", "smb-os-discovery", 
               "dns-brute", "snmp-sysdescr", "http-sql-injection", "ftp-bounce", 
               "smtp-open-relay", "pop3-brute", "imap-brute"]
nmap_flags = ["-sS", "-sT", "-sU", "-A", "-O", "-F", "--top-ports 10", "--version-light", 
              "-Pn", "-PE", "-PP", "-PM", "-PO", "-PS", "-PA", "-sV", "--traceroute", "-n", "-6"]

# Examples for each script and flag
script_examples = {
    "vuln": "Example: nmap <target> -p <port> --script vuln",
    "smtp-commands": "Example: nmap <target> -p 25 --script smtp-commands",
    "http-title": "Example: nmap <target> -p 80 --script http-title",
    "ftp-anon": "Example: nmap <target> -p 21 --script ftp-anon",
    "ssh-brute": "Example: nmap <target> -p 22 --script ssh-brute",
    "ssl-cert": "Example: nmap <target> -p 443 --script ssl-cert",
    "http-enum": "Example: nmap <target> -p 80 --script http-enum",
    "http-vuln-cve2017-5638": "Example: nmap <target> -p 80 --script http-vuln-cve2017-5638",
    "mysql-info": "Example: nmap <target> -p 3306 --script mysql-info",
    "smb-os-discovery": "Example: nmap <target> -p 445 --script smb-os-discovery",
    "dns-brute": "Example: nmap <target> -p 53 --script dns-brute",
    "snmp-sysdescr": "Example: nmap <target> -p 161 --script snmp-sysdescr",
    "http-sql-injection": "Example: nmap <target> -p 80 --script http-sql-injection",
    "ftp-bounce": "Example: nmap <target> -p 21 --script ftp-bounce",
    "smtp-open-relay": "Example: nmap <target> -p 25 --script smtp-open-relay",
    "pop3-brute": "Example: nmap <target> -p 110 --script pop3-brute",
    "imap-brute": "Example: nmap <target> -p 143 --script imap-brute"
}

flag_examples = {
    "-sS": "Example: nmap <target> -sS",
    "-sT": "Example: nmap <target> -sT",
    "-sU": "Example: nmap <target> -sU",
    "-A": "Example: nmap <target> -A",
    "-O": "Example: nmap <target> -O",
    "-F": "Example: nmap <target> -F",
    "--top-ports 10": "Example: nmap <target> --top-ports 10",
    "--version-light": "Example: nmap <target> --version-light",
    "-Pn": "Example: nmap <target> -Pn",
    "-PE": "Example: nmap <target> -PE",
    "-PP": "Example: nmap <target> -PP",
    "-PM": "Example: nmap <target> -PM",
    "-PO": "Example: nmap <target> -PO",
    "-PS": "Example: nmap <target> -PS",
    "-PA": "Example: nmap <target> -PA",
    "-sV": "Example: nmap <target> -sV",
    "--traceroute": "Example: nmap <target> --traceroute",
    "-n": "Example: nmap <target> -n",
    "-6": "Example: nmap <target> -6"
}

# Function to run the nmap scan
def run_scan():
    target = target_entry.get()
    ports = ports_entry.get()
    custom_flags = custom_flags_entry.get()
    selected_flag = flag_var.get()
    selected_script = script_var.get()
    aggressive_scan = aggressive_scan_var.get()

    if not target:
        messagebox.showerror("Error", "Target IP address is required.")
        return

    messagebox.showinfo("Scan Starting", f"Starting scan on {target}")

    scanner = nmap.PortScanner()
    
    # Construct the nmap command
    command = ""
    if aggressive_scan:
        command = "-A"
    else:
        if selected_flag:
            command += f"{selected_flag} "
        if custom_flags:
            command += f"{custom_flags} "
        if selected_script:
            command += f"--script={selected_script} "
    if ports:
        command += f"-p {ports} "
    else:
        command += "-p-"

    def scan():
        try:
            scanner.scan(target, arguments=command)
            result_text.delete(1.0, tk.END)
            for host in scanner.all_hosts():
                result_text.insert(tk.END, f"Host: {host} ({scanner[host].hostname()})\n")
                result_text.insert(tk.END, f"State: {scanner[host].state()}\n")
                for proto in scanner[host].all_protocols():
                    result_text.insert(tk.END, f"Protocol: {proto}\n")
                    lport = sorted(scanner[host][proto].keys())
                    for port in lport:
                        state = scanner[host][proto][port]['state']
                        result_text.insert(tk.END, f"Port: {port}\tState: {state}\n")
                        if 'script' in scanner[host][proto][port]:
                            for script, output in scanner[host][proto][port]['script'].items():
                                result_text.insert(tk.END, f"\tScript: {script}\n\tOutput: {output}\n")
                result_text.insert(tk.END, "\n")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    threading.Thread(target=scan).start()

# Function to clear flag selection
def clear_flag():
    flag_var.set("")
    flag_hint_label.config(text="")

# Function to clear script selection
def clear_script():
    script_var.set("")
    script_hint_label.config(text="")

# Function to update script hint
def update_script_hint(*args):
    selected_script = script_var.get()
    hint = script_examples.get(selected_script, "")
    script_hint_label.config(text=hint)

# Function to update flag hint
def update_flag_hint(*args):
    selected_flag = flag_var.get()
    hint = flag_examples.get(selected_flag, "")
    flag_hint_label.config(text=hint)

# Function to clear result text
def clear_result_text():
    result_text.delete(1.0, tk.END)

# Function to save result text to a file
def save_result_text():
    filetypes = [("Text files", "*.txt"), ("HTML files", "*.html"), ("All files", "*.*")]
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=filetypes)
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_text.get(1.0, tk.END))

# Create the main window
root = tk.Tk()
root.title("Nmap Scanner")
root.geometry("850x700")

# Add a frame for the form
form_frame = ttk.Frame(root, padding="10")
form_frame.grid(row=0, column=0, sticky=tk.W+tk.E)

# Add a frame for the result text
result_frame = ttk.Frame(root, padding="10")
result_frame.grid(row=1, column=0, sticky=tk.W+tk.E)

style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))
style.configure("TOptionMenu", font=("Helvetica", 12))

# Target input
ttk.Label(form_frame, text="Target:").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
target_entry = ttk.Entry(form_frame, width=50)
target_entry.grid(row=0, column=1, padx=10, pady=5)

# Ports input
ttk.Label(form_frame, text="Ports (optional, comma-separated):").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
ports_entry = ttk.Entry(form_frame, width=50)
ports_entry.grid(row=1, column=1, padx=10, pady=5)

# Manual flags input
ttk.Label(form_frame, text="Manual Flags (optional):").grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
custom_flags_entry = ttk.Entry(form_frame, width=50)
custom_flags_entry.grid(row=2, column=1, padx=10, pady=5)

# Flag selection
ttk.Label(form_frame, text="Select Flag:").grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)
flag_var = tk.StringVar(value="")
flag_var.trace("w", update_flag_hint)
flag_menu = ttk.OptionMenu(form_frame, flag_var, "", *nmap_flags)
flag_menu.grid(row=3, column=1, padx=10, pady=5)
clear_flag_button = ttk.Button(form_frame, text="Clear Flag", command=clear_flag)
clear_flag_button.grid(row=3, column=2, padx=10, pady=5)

# Script selection
ttk.Label(form_frame, text="Select NSE Script:").grid(row=4, column=0, padx=10, pady=5, sticky=tk.W)
script_var = tk.StringVar(value="")
script_var.trace("w", update_script_hint)
script_menu = ttk.OptionMenu(form_frame, script_var, "", *nse_scripts)
script_menu.grid(row=4, column=1, padx=10, pady=5)
clear_script_button = ttk.Button(form_frame, text="Clear Script", command=clear_script)
clear_script_button.grid(row=4, column=2, padx=10, pady=5)

# Script hint
script_hint_label = ttk.Label(form_frame, text="", font=("Helvetica", 10), foreground="gray")
script_hint_label.grid(row=5, column=1, padx=10, pady=5, sticky=tk.W)

# Flag hint
flag_hint_label = ttk.Label(form_frame, text="", font=("Helvetica", 10), foreground="gray")
flag_hint_label.grid(row=3, column=3, padx=10, pady=5, sticky=tk.W)

# Aggressive scan checkbox
aggressive_scan_var = tk.BooleanVar()
ttk.Checkbutton(form_frame, text="Aggressive Scan (-A)", variable=aggressive_scan_var).grid(row=6, column=0, columnspan=2, padx=10, pady=5)

# Scan button
scan_button = ttk.Button(form_frame, text="Run Scan", command=run_scan)
scan_button.grid(row=7, column=0, padx=10, pady=10)

# Clear result button
clear_result_button = ttk.Button(form_frame, text="Clear Result", command=clear_result_text)
clear_result_button.grid(row=7, column=1, padx=10, pady=10)

# Save result button
save_result_button = ttk.Button(form_frame, text="Save Result", command=save_result_text)
save_result_button.grid(row=7, column=2, padx=10, pady=10)

# Result text
result_text = tk.Text(result_frame, width=80, height=20)
result_text.grid(row=0, column=0, padx=10, pady=10)

# Add a scrollbar to the result text
scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=result_text.yview)
scrollbar.grid(row=0, column=1, sticky=tk.N+tk.S+tk.W)
result_text.configure(yscrollcommand=scrollbar.set)

root.mainloop()

