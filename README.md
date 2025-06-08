# arpwake
Listens for ARP requests and sends Wake-on-LAN packets to a machine that should wake on network access.

Inspired by https://github.com/danielpgross/friendly_neighbor

## Building

This is a service that has minimal dependencies and should be portable to many different Linux environments.

It has been tested on `armv6l` on a Raspberry Pi Zero W but of course YMMV.

`gcc -o arpwake src/arpwake.c`

## Installing

```
sudo cp arpwake /usr/local/bin/arpwake  # or wherever you wish to install
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/arpwake  # grant networking capabilities so we don't need to run as root

# Create a systemd service to run automatically
sudo cp arpwake.service /etc/systemd/system/arpwake.service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now arpwake.service
```

## Usage example

[Hardware info](https://samwinslow.com/post/nas-build-2025)

The author's use case is to wake a NAS or other targeted device on any network access, not just magic packets. The targeted device should have wake-on-LAN (magic packets) enabled and have a static DHCP lease/fixed IPv4 address.

`Usage: arpwake --iface <iface> --target-ip <target_ip> --wol-mac <mac_str> --wol-broadcast <broadcast_ip>`

- iface: network interface to bind, e.g. `wlan0`, `eth0`
- target_ip: IPv4 address of the device to wake
- wol_mac: MAC address of the device to wake
- broadcast_ip: Broadcast address e.g. `192.168.0.255`, `255.255.255.255`

