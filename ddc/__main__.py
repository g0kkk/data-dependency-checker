#!/usr/bin/python3

from ddc import arsenal


def main():
    parser = argparse.ArgumentParser(description="Data dependency checker")
    parser.add_argument('-b', 'binary', help="the path to the target binary to be fuzzed")
    parser.add_argument('-addr', 'address', help="address at which the dependency needs to be checked", default=0)
    parser.add_argument('-a', 'arch', help="which arch -- x86 or x86_64", default="x86_64")

    args = parser.parse_args()
    value = 0
    obj = arsenal.Bazooka(target=args.binary, arch=args.arch, addr=args.addr, value=value)
    obj.load_bin()
