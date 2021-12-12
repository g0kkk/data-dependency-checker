class Bazooka:
    def __init__(self, target, arch, addr, value):
        self.target = target
        self.arch = arch
        self.addr = addr
        self.value = value

    @staticmethod
    def legendary(*args, **kwargs):
        from .runner import Check
        return Check(**kwargs)
