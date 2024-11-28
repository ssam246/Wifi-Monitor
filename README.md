# **WiFi Monitor Tool**

A powerful and user-friendly tool to monitor nearby WiFi networks. This tool allows you to sniff WiFi packets, identify available networks, and display essential details like SSID, BSSID, signal strength, frequency, and data rate. Built using Scapy, it supports monitor mode interfaces and provides real-time feedback.

---

## **Features**

- **Monitor Mode Handling**:
  - Automatically enables monitor mode on the selected network interface.
  - Detects if the interface is already in monitor mode to avoid redundant operations.

- **WiFi Packet Sniffing**:
  - Sniffs nearby WiFi packets to detect networks.
  - Extracts critical details such as SSID, BSSID, signal strength, channel frequency, and data rate.

- **Duplicate Detection**:
  - Ensures no duplicate networks are displayed by tracking unique BSSIDs.

- **Customizable Monitoring Duration**:
  - Use the `--timeout` option to set the monitoring duration (default: 30 seconds).

- **Formatted Output**:
  - Displays network details in a clean, tabulated format using `tabulate`.

- **Error Handling**:
  - Provides clear error messages for invalid interface selection, permission issues, or other runtime errors.

---

## **Prerequisites**

- Python 3.10.10 installed on your system.
- Required libraries: Install dependencies using `pip`:
  ```bash
  pip install scapy tabulate
  ```

- **Permissions**:
  - This tool requires root or administrative privileges to enable monitor mode and sniff packets.

---

## **Installation**

1. **Clone the Repository**:
   ```bash
   git clone [repository URL]
   cd [repository folder]
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## **Usage**

### **Basic Usage**:
Run the tool without any arguments, and it will prompt you to select a network interface:
```bash
sudo python wifi_monitor.py
```

### **Specify Interface and Timeout**:
You can specify the network interface and monitoring duration directly:
```bash
sudo python wifi_monitor.py -i wlan0 -t 60
```

### **Command-Line Options**:
| Option             | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `-i, --interface`  | Specify the network interface to use for monitoring.                       |
| `-t, --timeout`    | Set the monitoring duration in seconds (default: 30 seconds).              |

---

## **Output Example**

When WiFi networks are detected, the tool displays them in a formatted table:
```text
Monitoring WiFi on interface wlan0... (Timeout: 30s)
Press Ctrl+C to stop early.

+-------------------+-------------------+----------------------+------------------+-------------------+
| SSID              | BSSID            | Signal Strength (dBm)| Frequency (MHz) | Data Rate (Mbps)  |
+-------------------+-------------------+----------------------+------------------+-------------------+
| HomeNetwork       | 00:14:22:01:23:45| -40                  | 2412            | 54                |
| GuestWiFi         | 00:16:35:42:11:89| -55                  | 2437            | 48                |
+-------------------+-------------------+----------------------+------------------+-------------------+
```

If no networks are found:
```text
No networks detected. Try increasing the monitoring duration.
```

---

## **Troubleshooting**

- **Permission Denied**:
  - Run the script with `sudo` to ensure sufficient permissions.
  
- **No Interfaces Found**:
  - Ensure your network card is installed and detected by your system. Use `ifconfig` to check.

- **Interface Not in Monitor Mode**:
  - The script automatically attempts to enable monitor mode, but ensure your wireless card supports it. Use the `iwconfig` command to verify.

---

## **Contributing**

We welcome contributions to enhance this tool!  
To contribute:
1. Fork the repository.
2. Implement your changes or fix issues.
3. Submit a pull request with a detailed description of your improvements.

---

## **License**

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE.md) file for details.

---

## **Disclaimer**

This tool is intended for **educational and ethical purposes only**.  
The author does not condone the use of this tool for illegal or malicious activities.  
Ensure you have proper authorization before sniffing any WiFi networks.

---

### **Made with 💻 and 🔍 by Stephen**
