#!/usr/bin/python3

import argparse
import ddc


def main():
    parser = argparse.ArgumentParser(description="Helper script to invoke DDS")
    parser.add_argument("-b", "--target", help="Path to target binary")
    parser.add_argument("-a", "--addr", help="address at which the check needs to be done")
    parser.add_argument("-p", "--project-type", help="either x86 or x86_64")

    args = parser.parse_args()
    obj = ddc.Check(target=args.target, addr=args.addr, arch=args.project_type, value=0)
    obj.load_bin()