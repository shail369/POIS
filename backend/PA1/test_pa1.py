from owf import DLP_OWF
from prg import PRG
from tests import frequency_test, runs_test, serial_test


def test_owf():
    print("\n=== Testing OWF ===")
    owf = DLP_OWF()

    x = input("Enter input x (default 12345): ") or "12345"
    x = int(x)
    y = owf.evaluate(x)

    print(f"f({x}) = {y}")
    print()


def test_prg():
    print("\n=== Testing PRG ===")
    owf = DLP_OWF()
    prg = PRG(owf)

    seed = input("Enter seed (default 123456789): ") or "123456789"
    length = input("Enter number of bits (default 64): ")

    length = int(length) if length else 64

    prg.seed(seed)
    bits = prg.next_bits(length)

    print("\nGenerated bits:")
    print(bits)
    print(f"Length: {len(bits)}\n")

    return bits


def test_statistical_tests(bits):
    print("\n=== Statistical Tests ===")

    freq = frequency_test(bits)
    runs = runs_test(bits)
    serial = serial_test(bits)

    print(f"Frequency: p={freq['p_value']:.4f} → {'PASS' if freq['pass'] else 'FAIL'}")
    print(f"Runs:      p={runs['p_value']:.4f} → {'PASS' if runs['pass'] else 'FAIL'}")
    print(f"Serial:    p1={serial['p_value1']:.4f}, p2={serial['p_value2']:.4f} → {'PASS' if serial['pass'] else 'FAIL'}")
    print()


def test_hardness():
    print("\n=== Testing OWF Hardness ===")
    owf = DLP_OWF()

    owf.verify_hardness()
    print()


def run_all():
    print("\n🚀 Running ALL tests\n")

    test_owf()
    bits = test_prg()
    test_statistical_tests(bits)
    test_hardness()


def main():
    last_bits = None

    while True:
        print("\n========= Crypto Test Menu =========")
        print("1. Test OWF")
        print("2. Test PRG")
        print("3. Run Statistical Tests")
        print("4. Test OWF Hardness")
        print("5. Run ALL")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            test_owf()

        elif choice == "2":
            last_bits = test_prg()

        elif choice == "3":
            if last_bits is None:
                print("No bits available. Running PRG first...")
                last_bits = test_prg()
            test_statistical_tests(last_bits)

        elif choice == "4":
            test_hardness()

        elif choice == "5":
            run_all()

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()