 # Nmap Scanner GUI

Welcome to the Nmap Scanner GUI, an intuitive interface for performing network scans using Nmap. This project is designed to help users perform various Nmap scans with ease.

**Features**

- Graphical User Interface (GUI) built with Tkinter.
- Support for various Nmap scan flags and NSE scripts.
- Aggressive scan mode.
- Display scan results in a text area.
- Save scan results to a file.

## Requirements

- Python 3.x
- tkinter (usually included with Python standard library)
- python-nmap
- colorama

**Installation**

1. Clone this repository:

git clone https://github.com/yourusername/nmap-scanner-gui.git
cd nmap-scanner-gui
install the required system packages:

**On Debian-based systems (e.g., Ubuntu):**

sudo apt-get install python3-tk

**On Red Hat-based systems (e.g., CentOS):**

sudo yum install python3-tkinter

**On macOS:**

brew install python-tk

**Install all dependencies via the provided script:**

python requirements.py


**Usage**
Run the Nmap Scanner GUI:
python nmap2.py

Enter the target IP address or hostname.
Optionally, specify ports (comma-separated) and custom flags.
Select a scan flag and/or NSE script from the dropdown menus.
Check the "Aggressive Scan (-A)" checkbox for an aggressive scan.
Click the "Run Scan" button to start the scan.
View the results in the text area.
Optionally, clear the results or save them to a file using the provided buttons.

**Example Scripts and Flags**

vuln: Example: nmap <target> -p <port> --script vuln
smtp-commands: Example: nmap <target> -p 25 --script smtp-commands
http-title: Example: nmap <target> -p 80 --script http-title
ftp-anon: Example: nmap <target> -p 21 --script ftp-anon
ssh-brute: Example: nmap <target> -p 22 --script ssh-brute
ssl-cert: Example: nmap <target> -p 443 --script ssl-cert
and more...

**Nmap Flags** 
-sS: Example: nmap <target> -sS
-sT: Example: nmap <target> -sT
-sU: Example: nmap <target> -sU
-A: Example: nmap <target> -A
-O: Example: nmap <target> -O
-F: Example: nmap <target> -F
--top-ports 10: Example: nmap <target> --top-ports 10
and more...

**Contributing**
Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

**License**
This project is licensed under the MIT License.

**Author** 
This script is owned by Winston Ighodaro. Visit me at https://store.cybergenereation.tech
