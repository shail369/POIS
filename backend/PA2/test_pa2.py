from prf import GGM_PRF
from prg_from_prf import PRG_from_PRF
from distinguisher import distinguishing_game


def test_prf():
    print("\n=== GGM PRF ===")
    prf = GGM_PRF()

    k_input = input("Enter key (default 123456): ") or "123456"
    x = input("Enter input bits (default 0101): ") or "0101"

    k = int(k_input) if k_input else 123456

    result = prf.F(k, x)

    print(f"\nF({k}, {x}) = {result}")
    print()


def test_prg_from_prf():
    print("\n=== PRG from PRF ===")
    prg = PRG_from_PRF()

    seed_input = input("Enter seed (default 123456): ") or "123456"
    seed = int(seed_input) if seed_input else 123456

    out = prg.generate(seed)

    print("\nOutput:")
    print(out)
    print()


def test_distinguisher():
    print("\n=== Distinguishing Game ===")

    rounds_input = input("Enter number of rounds (default 100): ")
    rounds = int(rounds_input) if rounds_input else 100

    distinguishing_game(q=rounds)

    print()


def run_all():
    print("\n🚀 Running ALL tests\n")

    prf = GGM_PRF()
    print("PRF Example:")
    print(f"F(123456, 0101) = {prf.F(123456, '0101')}\n")

    prg = PRG_from_PRF()
    print("PRG from PRF Output:")
    print(prg.generate(123456), "\n")

    print("Distinguishing Game:")
    distinguishing_game()


def main():
    while True:
        print("\n========= PRF Test Menu =========")
        print("1. Test GGM PRF")
        print("2. Test PRG from PRF")
        print("3. Run Distinguishing Game")
        print("4. Run ALL")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            test_prf()

        elif choice == "2":
            test_prg_from_prf()

        elif choice == "3":
            test_distinguisher()

        elif choice == "4":
            run_all()

        elif choice == "0":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()