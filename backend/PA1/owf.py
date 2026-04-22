import random

class DLP_OWF:
    def __init__(self):
        self.p = 2147483647
        self.g = 5

    def evaluate(self, x):
        return pow(self.g, x, self.p)

    def verify_hardness(self, trials=5):
        print("Testing OWF hardness...")

        for _ in range(trials):
            x = random.randint(1, 100000)
            y = self.evaluate(x)

            found = False
            for guess in range(10000):
                if self.evaluate(guess) == y:
                    found = True
                    break

            print(f"x={x}, inversion success={found}")