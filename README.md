# BLE Relay over MQTT

**English** | [中文](README_zh.md)

A BLE (Bluetooth Low Energy) link-layer relay attack tool using MQTT for long-range, cross-network communication. Built on top of the [Sniffle](https://github.com/nccgroup/Sniffle) BLE sniffer framework.

## Overview

Traditional BLE relay attacks require both relay nodes to be on the same local network (TCP direct connection). This tool overcomes that limitation by using an MQTT broker as the transport layer, enabling relay attacks across the internet — from anywhere to anywhere.

```
┌──────────────────┐         ┌──────────────────┐         ┌──────────────────┐
│   Phone/Central  │◄──BLE──►│  relay_peripheral │         │                  │
│  (e.g., App)     │         │  (Phone-side)     │         │   MQTT Broker    │
└──────────────────┘         │  + Sniffle Board  │◄──MQTT──►  (Public Server) │
                             └──────────────────┘         │                  │
                                                          └────────┬─────────┘
                                                                   │ MQTT
                             ┌──────────────────┐                  │
                             │   relay_central   │◄─────────────────┘
                             │  (Device-side)    │
                             │  + Sniffle Board  │◄──BLE──►┌──────────────────┐
                             └──────────────────┘         │  BLE Peripheral  │
                                                          │  (e.g., Car PKE) │
                                                          └──────────────────┘
```

## How It Works

1. **Device-side** (`relay_central.py`) scans and captures the target peripheral's ADV_IND + SCAN_RSP
2. Captured advertisement data is published to the MQTT broker (with retain flag)
3. **Peripheral-side** (`relay_peripheral.py`) subscribes to MQTT, receives the advertisement, and clones the target's BLE identity
4. The peripheral-side starts advertising, waiting for the legitimate central (phone) to connect
5. When the phone connects, the CONNECT_IND is forwarded via MQTT to the device-side
6. The device-side uses the CONNECT_IND parameters to establish a real BLE connection to the peripheral
7. All subsequent link-layer data PDUs are bidirectionally relayed through MQTT

## Prerequisites

### Hardware

- **2× TI CC1352/CC2652 development boards** (e.g., LAUNCHXL-CC1352R1 or LAUNCHXL-CC26X2R1) flashed with [Sniffle firmware](https://github.com/nccgroup/Sniffle)
- USB cables for connecting boards to computers

### Software

- Python 3.8+
- An MQTT broker accessible from both relay nodes (e.g., [Mosquitto](https://mosquitto.org/), [EMQX](https://www.emqx.io/))

### MQTT Broker Setup

You need a publicly accessible MQTT broker. Options:

1. **Self-hosted Mosquitto** (recommended):
   ```bash
   # On your VPS/cloud server
   sudo apt install mosquitto mosquitto-clients
   sudo systemctl enable --now mosquitto
   ```

2. **Cloud MQTT services**: EMQX Cloud, HiveMQ Cloud, etc.

> ⚠️ For security research only. Ensure proper authentication on production MQTT brokers.

## Installation

```bash
git clone https://github.com/yourname/RelayonMQTT.git
cd RelayonMQTT
pip install -r requirements.txt
```

## Usage

### Step 1: Start the Device-side Relay (near the target peripheral)

```bash
python relay_central.py -B <MQTT_BROKER_IP> -t <TARGET_MAC> -s <SERIAL_PORT>
```

Example:
```bash
python relay_central.py -B mqtt.example.com -t C6:07:59:15:53:5F -s /dev/ttyACM0
```

### Step 2: Start the Peripheral-side Relay (near the phone/central)

```bash
python relay_peripheral.py -B <MQTT_BROKER_IP> -s <SERIAL_PORT>
```

Example:
```bash
python relay_peripheral.py -B mqtt.example.com -s /dev/ttyACM1
```

> **Note:** Thanks to MQTT retained messages, the startup order does not matter. The device-side relay publishes advertisement data with the retain flag, so the peripheral-side relay will receive it even if it starts later.

### Command-Line Options

#### `relay_central.py` (Device-side)

| Option | Description | Default |
|--------|-------------|---------|
| `-B`, `--broker` | MQTT broker address (required) | — |
| `-P`, `--mqtt-port` | MQTT broker port | 1883 |
| `-t`, `--target` | Target BLE MAC address (required) | — |
| `-s`, `--serport` | Sniffle serial port | auto-detect |
| `-o`, `--output` | PCAP output file | none |
| `-q`, `--quiet` | Suppress per-packet output | false |
| `--pub-topic` | MQTT publish topic | `/ble_relay/to_phone` |
| `--sub-topic` | MQTT subscribe topic | `/ble_relay/to_device` |

#### `relay_peripheral.py` (Peripheral-side)

| Option | Description | Default |
|--------|-------------|---------|
| `-B`, `--broker` | MQTT broker address (required) | — |
| `-P`, `--mqtt-port` | MQTT broker port | 1883 |
| `-s`, `--serport` | Sniffle serial port | auto-detect |
| `-o`, `--output` | PCAP output file | none |
| `-q`, `--quiet` | Suppress per-packet output | false |
| `--pub-topic` | MQTT publish topic | `/ble_relay/to_device` |
| `--sub-topic` | MQTT subscribe topic | `/ble_relay/to_phone` |

## Protocol

Messages exchanged between relay nodes use a simple text protocol over MQTT:

| Prefix | Direction | Description |
|--------|-----------|-------------|
| `adv:<hex>` | Device → Peripheral | Full ADV_IND PDU body |
| `rsp:<hex>` | Device → Peripheral | Full SCAN_RSP PDU body |
| `con:<hex>` | Peripheral → Device | CONNECT_IND PDU body |
| `dat:<event_hex>:<pdu_hex>` | Bidirectional | Data PDU with event counter |

## Packet Capture

Both relay scripts support PCAP output (`-o` flag) for offline analysis in Wireshark:

```bash
# Device-side with capture
python relay_central.py -B broker.example.com -t AA:BB:CC:DD:EE:FF -s /dev/ttyACM0 -o device_capture.pcapng

# Peripheral-side with capture
python relay_peripheral.py -B broker.example.com -s /dev/ttyACM1 -o peripheral_capture.pcapng
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| "Waiting for advertisement data..." hangs | Device-side not running or broker unreachable | Check broker connectivity; start device-side first |
| Peripheral-side never sees phone connect | Phone not in range, or advertisement data incorrect | Ensure phone BLE scanning is active; check target MAC |
| "HW packet error" messages | Sniffle firmware issue or USB disconnect | Reconnect board, re-flash firmware |
| High latency / dropped packets | Network latency to broker | Use broker geographically close to both nodes |

## Limitations

- Only supports legacy advertising (ADV_IND + SCAN_RSP), not extended advertising
- Relay latency depends on network round-trip to MQTT broker
- Does not handle BLE encryption (attacker must relay before pairing/bonding)
- Single connection at a time

## Credits

- [Sniffle](https://github.com/nccgroup/Sniffle) by Sultan Qasim Khan (NCC Group) — BLE sniffer framework
- MQTT transport concept for extending BLE relay range beyond local networks

## License

This project is licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

This is a derivative work based on Sniffle (GPLv3).

## Disclaimer

This tool is intended for authorized security research and testing only. Users are responsible for complying with all applicable laws. Do not use this tool against systems you do not own or have explicit written permission to test.
