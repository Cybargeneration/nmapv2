# Install required packages using pip
import subprocess
import sys
import os

# Function to install a package using pip
def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Function to install a package using the system package manager
def install_system_package(package):
    if os.name == 'posix':
        if os.path.isfile('/etc/debian_version'):
            subprocess.check_call(["sudo", "apt-get", "install", "-y", package])
        elif os.path.isfile('/etc/redhat-release'):
            subprocess.check_call(["sudo", "yum", "install", "-y", package])
        elif os.path.isfile('/etc/arch-release'):
            subprocess.check_call(["sudo", "pacman", "-S", "--noconfirm", package])
        elif os.path.isfile('/etc/alpine-release'):
            subprocess.check_call(["sudo", "apk", "add", package])
        else:
            print("Unsupported Linux distribution.")
            return False
    elif os.name == 'darwin':
        subprocess.check_call(["brew", "install", package])
    else:
        print("Unsupported OS.")
        return False
    return True

# Install tkinter
try:
    install_system_package("python3-tk")
    print("Successfully installed tkinter")
except Exception as e:
    print(f"Failed to install tkinter: {e}")

# Install python-nmap
try:
    install_package("python-nmap")
    print("Successfully installed python-nmap")
except Exception as e:
    print(f"Failed to install python-nmap: {e}")

# Install colorama
try:
    install_package("colorama")
    print("Successfully installed colorama")
except Exception as e:
    print(f"Failed to install colorama: {e}")

print("All required packages are installed.")

