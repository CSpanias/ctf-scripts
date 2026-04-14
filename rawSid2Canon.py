#!/usr/bin/env python3
"""
A utility to convert a raw hexadecimal SID into its canonical, human-readable
S-1- format.
"""
from impacket.dcerpc.v5.dtypes import SID
import sys

# Define some ANSI color codes for prettier output
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def main():
    """Main function to prompt for, convert, and print the SID."""
    print(f"{Colors.BOLD}{Colors.BLUE}--- Raw SID to Canonical SID Converter ---{Colors.ENDC}")

    # Get user input with a clear prompt
    raw_sid_hex = input(f"{Colors.YELLOW}> Enter the raw SID in hex format: {Colors.ENDC}")

    # Exit gracefully if the user provides no input
    if not raw_sid_hex.strip():
        print(f"\n{Colors.RED}Error: No input provided. Exiting.{Colors.ENDC}")
        sys.exit(1)

    try:
        # Convert the hex string into a SID object
        # 1. `bytes.fromhex()`: Converts the hex string to a byte sequence.
        # 2. `SID()`: Parses the bytes into an Impacket SID object.
        sid_object = SID(data=bytes.fromhex(raw_sid_hex))

        # `formatCanonical()`: Converts the SID object to the S-1-... string.
        canonical_sid = sid_object.formatCanonical()

        # Print the final result
        print(f"\n{Colors.GREEN}Canonical SID: {Colors.BOLD}{canonical_sid}{Colors.ENDC}\n")

    except ValueError:
        # Catch errors if the input is not valid hexadecimal
        print(f"\n{Colors.RED}Error: Invalid input. Please provide a valid hexadecimal string.{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        # Catch any other unexpected errors
        print(f"\n{Colors.RED}An unexpected error occurred: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
