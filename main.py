"""Interactive VG-21 tool: VG-21C compression + Base95 text encoding."""
from encoder import encode_text, encode_file
from decoder import decode_text, decode_file


def main():
    while True:
        print("\n" + "=" * 46)
        print("              VG-21 TOOL")
        print("       VG-21C -> Base95 (78/95)")
        print("=" * 46)
        print("1. Encode text")
        print("2. Decode text")
        print("3. Encode file")
        print("4. Decode file")
        print("0. Exit")
        print("=" * 46)
        choice = input("Choose an option: ").strip()
        try:
            if choice == "1":
                text = input("Enter text: ")
                encoded = encode_text(text)
                print("\nEncoded VG-21 text:\n" + encoded)
                print(f"\nEncoded characters: {len(encoded):,}")
                if input("Save to TXT? (y/n): ").strip().lower() == "y":
                    path = input("Output TXT path: ").strip().strip('"')
                    with open(path, "w", encoding="ascii", newline="") as file:
                        file.write(encoded)
                    print(f"Saved to: {path}")
            elif choice == "2":
                path = input("Encoded TXT path: ").strip().strip('"')
                with open(path, "r", encoding="ascii", newline="") as file:
                    encoded = file.read()
                print("\nDecoded text:")
                print(decode_text(encoded))
            elif choice == "3":
                source = input("Original file path: ").strip().strip('"')
                destination = input("Output encoded TXT path: ").strip().strip('"')
                encode_file(source, destination)
            elif choice == "4":
                source = input("Encoded TXT path: ").strip().strip('"')
                destination = input("Decoded output file path: ").strip().strip('"')
                decode_file(source, destination)
            elif choice == "0":
                print("Goodbye!")
                break
            else:
                print("Invalid option. Choose 0-4.")
        except Exception as error:
            print(f"\nError: {error}")


if __name__ == "__main__":
    main()
