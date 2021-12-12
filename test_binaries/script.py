import ddc
obj = ddc.Check(target="./hello", addr=0x0000000000400b8a, arch="x86_64", value=0) 
obj.load_bin()
