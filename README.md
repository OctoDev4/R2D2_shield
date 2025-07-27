

🛡️ R2D2 Shield: Lightweight ARP Spoofing Detector with Galactic Style
R2D2 Shield is a simple yet powerful network security tool designed to detect ARP spoofing attacks in real time. Inspired by the iconic astromech droid from Star Wars, this project acts as a vigilant guardian of your local network—always alert, always loyal.

⚙️ Features
🚨 ARP Spoofing Detection: Monitors ARP traffic and identifies mismatches between real and spoofed MAC addresses.

🎯 MAC Verification: Sends ARP requests to validate the authenticity of devices on the network.

🌈 Color-coded Output: Uses colorama to highlight alerts and make logs easy to read.

🧠 Command-line Interface: Customizable via argparse for flexible usage.

🧪 How It Works
R2D2 Shield listens to ARP traffic on the specified network interface. When it detects an ARP reply (op=2), it checks whether the MAC address associated with the source IP matches the real MAC obtained via an ARP request. If there's a mismatch, it raises an alert—just like R2D2 flashing a warning light!

🚀 Usage
```bash
python r2d2_shield.py -i wlan0
#Replace wlan0 with your desired network interface.
```
