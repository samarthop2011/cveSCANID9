
#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import ssl
import urllib.request
import urllib.error
import json
import base64
import getpass
from concurrent.futures import ThreadPoolExecutor, as_completed

REDFISH = "/redfish/v1/Managers/iDRAC.Embedded.1"
TIMEOUT = 3

def check_firmware(version):
    try:
        v = tuple(int(x) for x in version.split("."))
        v = (v + (0, 0, 0, 0))[:4]
    except (ValueError, AttributeError):
        return "UNKNOWN"

    if v[:2] == (3, 24):
        return "VULNERABLE" if v < (3, 24, 24, 24) else "NOT FLAGGED"

    if v[:2] == (3, 22):
        return "VULNERABLE" if v < (3, 22, 22, 22) else "NOT FLAGGED"

    if v[:2] == (3, 21):
        if v in ((3, 21, 25, 22), (3, 21, 26, 22)):
            return "NOT FLAGGED"
        return "REVIEW"

    return "UNKNOWN"


def scan(ip, auth):
    try:
        sock = socket.create_connection((str(ip), 443), TIMEOUT)
        sock.close()
    except OSError:
        return None

    url = f"https://{ip}{REDFISH}"

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "SAM-InfraScanner/1.0",
            **({"Authorization": auth} if auth else {})
        }
    )

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )

        with opener.open(request, timeout=TIMEOUT) as response:
            data = json.loads(response.read().decode())

        firmware = data.get("FirmwareVersion", "")
        model = data.get("Model", "iDRAC/Redfish")

        if not firmware:
            return (str(ip), "UNKNOWN", "-", model)

        status = check_firmware(firmware)

        return (str(ip), status, firmware, model)

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return (str(ip), "AUTH REQUIRED", "-", "Redfish")
        return (str(ip), "UNKNOWN", "-", f"HTTP {e.code}")

    except Exception:
        return (str(ip), "UNKNOWN", "-", "Could not identify device")


def main():
    parser = argparse.ArgumentParser(
        description="SAM InfraScanner - iDRAC9 CVE-2019-3706 checker"
    )

    parser.add_argument("subnet", help="Authorized IP or CIDR")
    parser.add_argument("--username", help="Authorized Redfish username")
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.subnet, strict=False)
    except ValueError:
        parser.error("Invalid IP address or subnet")

    if network.num_addresses > 4096:
        parser.error("Maximum 4096 addresses per scan")

    auth = None

    if args.username:
        password = getpass.getpass("Redfish password: ")
        credentials = base64.b64encode(
            f"{args.username}:{password}".encode()
        ).decode()
        auth = f"Basic {credentials}"

    hosts = (
        list(network.hosts())
        if network.version == 4 and network.prefixlen < 31
        else list(network)
    )

    print("\n======================================")
    print("       SAM INFRASCANNER")
    print("======================================")
    print(f"Target: {network}")
    print(f"Addresses: {len(hosts)}")
    print("CVE: CVE-2019-3706")
    print("--------------------------------------")

    counts = {}

    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = [
            executor.submit(scan, ip, auth)
            for ip in hosts
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is None:
                continue

            ip, status, firmware, model = result
            counts[status] = counts.get(status, 0) + 1

            print(
                f"[{status}] {ip} | "
                f"Firmware: {firmware} | {model}"
            )

    print("\n======================================")
    print("             SCAN SUMMARY")
    print("======================================")

    for status, count in sorted(counts.items()):
        print(f"{status}: {count}")

    print("--------------------------------------")
    print("Scan finished.")
    print("No authentication bypass was attempted.")
    print("Verify findings against Dell DSA-2019-028.")


if __name__ == "__main__":
    main()
