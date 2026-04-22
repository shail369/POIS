class PRG:
    def __init__(self, owf):
        self.owf = owf
        self.state = None

    def seed(self, s):
        try:
            self.state = int(s) % (2**64)
        except:
            self.state = 123

    def next_bits(self, n):
        x = self.state
        bits = []

        for _ in range(n):
            x = self.owf.evaluate(x)
            bits.append(str(x & 1))

        return "".join(bits)
