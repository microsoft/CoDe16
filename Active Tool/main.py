import argparse
from codesysv3_protocol import *
from log import init_logger
from ipaddress import ip_address, IPv4Address


def is_legal_ip_address(ip: str) -> bool:
    try:
        return isinstance(ip_address(ip), IPv4Address)
    except:
        return False


def print_device_info(device_info: dict):
    print("Device Info:")
    print("\tNode Name:", device_info['node_name'])
    print("\tDevice Name:", device_info['device_name'])
    print("\tVendor Name:", device_info['vendor_name'])
    print("\tFirmware:", device_info['firmware_str'])


def main():
    init_logger()
    logger = logging.getLogger("Codesys")
    parser = argparse.ArgumentParser(description='Welcome to RTS Version extractor.')
    parser.add_argument('--username', type=str, default="", required=False,
                        help='The username that required to log into the plc.')
    parser.add_argument('--password', type=str, default="", required=False,
                        help='The password that required to log into the plc.')
    parser.add_argument('--dst_ip', type=str, default=None, required=True,
                        help='The IP address of the remote plc.')
    parser.add_argument('--src_ip', type=str, default=None, required=True,
                        help='The IP address of the machine that will run this script.')
    args = parser.parse_args()

    if False in (is_legal_ip_address(args.dst_ip), is_legal_ip_address(args.src_ip)):
        parser.error("Illegal IP address")

    try:
        rtsversion = None
        with CodeSysV3Device(args.dst_ip, args.src_ip) as device:
            device_info = device.get_device_name_server_info()
            print_device_info(device_info)
            if "codesys" in device_info['device_name'].lower() or "3s - smart software" in  device_info['vendor_name'].lower():
                rtsversion = device_info['firmware_str']
            else:
                logger.info("Failed to get info from the device NSServer, trying to run PLCShell command")
                with device.open_channel() as channel:
                    if not channel.login(args.username, args.password):
                        logger.error("Failed to login into the PLC")
                    else:
                        try:
                            shell = PLCShell(channel)
                            version = shell.run("rtsinfo")
                            rtsversion = version.split(":")[1].strip()
                        except Exception as ex:
                            logger.error("Failed to run PLCShell command")
            if rtsversion is not None:
                print(f"CodeSysV3 version: {rtsversion}")
            else:
                print("Failed to find the CodeSysV3 version")

    except Exception as ex:
        logger.error(f"Failed to extract the Codesys V3 Version from the PLC: {ex}")


if __name__ == '__main__':
    main()

