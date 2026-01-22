def vigenere_encrypt():
    """
    Encrypts the plaintext using the Vigenere Cipher with the given key.

    Args:
    plaintext (str): The text to encrypt (case-insensitive, non-letters unchanged).
    key (str): The keyword (case-insensitive).

    Returns:
    str: The encrypted ciphertext.
    """
    # Prompt for plaintext until non-empty1
    plaintext = ""
    while not plaintext or not any(c.isalpha() for c in plaintext):
        plaintext = input("Enter the plaintext: ").strip()
        if not plaintext:
            print("Plaintext cannot be empty. Please try again.")
        elif not any (c.isalpha() for c in plaintext):
            print("Plaintext must contain at least one letter. Please try again.")

    # Prompt for key until valid (contains at least one letter)
    key = ""
    while not key or not any(c.isalpha() for c in key):
        key = input("Enter the key: ").strip()
        if not key:
            print("Key cannot be empty. Please try again.")
        elif not any(c.isalpha() for c in key):
            print("Key must contain at least one letter. Please try again.")

    # Convert to uppercase and prepare key
    plaintext = plaintext.upper()
    key = key.upper()

    # Remove non-alphabetic characters from key for simplicity
    key = ''.join(c for c in key if c.isalpha())

    analyze_key_strength(key)

    # Encryption with step-by-step display
    print(f"\nPlaintext: {plaintext}")
    print(f"Key:       {key}")
    print("\nEncryption Process:")

    # Repeat key to match plaintext length (ignoring non-letters)
    key_repeated = ''
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            key_repeated += key[key_index % len(key)]
            key_index += 1
        else:
            key_repeated += char  # Keep non-letters as is

    # Encrypt
    ciphertext = ''
    for p, k in zip(plaintext, key_repeated):
        if p.isalpha():
            # Vigenere shift: (plaintext index + key index) mod 26
            p_index = ord(p) - ord('A')
            k_index = ord(k) - ord('A')
            c_index = (p_index + k_index) % 26
            ciphertext += chr(c_index + ord('A'))
        else:
            ciphertext += p


    print(f"Key (repeated): {key_repeated}")
    print(f"Ciphertext:     {ciphertext}")

    again = input("\nDo another operation? (Y/N): ").strip().upper()
    if again != 'Y':
        return False  # Signal to exit
    return True  # Signal to continue


def vigenere_decrypt():
    """
    Decrypts the ciphertext using the Vigenere Cipher with the given key.

    Args:
    ciphertext (str): The text to decrypt (case-insensitive, non-letters unchanged).
    key (str): The keyword (case-insensitive).

    Returns:
    str: The decrypted plaintext.
    """
    # Prompt for ciphertext until non-empty
    ciphertext = ""
    while not ciphertext  or not any(c.isalpha() for c in ciphertext):
        ciphertext = input("Enter the ciphertext: ").strip()
        if not ciphertext:
            print("Ciphertext cannot be empty. Please try again.")
        elif not any(c.isalpha() for c in ciphertext):
            print("Ciphertext must contain at least one letter. Please try again.")

    # Prompt for key until valid (contains at least one letter)
    key = ""
    while not key or not any(c.isalpha() for c in key):
        key = input("Enter the key: ").strip()
        if not key:
            print("Key cannot be empty. Please try again.")
        elif not any(c.isalpha() for c in key):
            print("Key must contain at least one letter. Please try again.")

    # Convert to uppercase and prepare key
    ciphertext = ciphertext.upper()
    key = key.upper()

    # Remove non-alphabetic characters from key
    key = ''.join(c for c in key if c.isalpha())

    """Decryption step-by-step display"""
    print(f"\nCiphertext: {ciphertext}")
    print(f"Key:       {key}")
    print("\nDecryption Process:")

    # Repeat key to match ciphertext length (ignoring non-letters)
    key_repeated = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            key_repeated += key[key_index % len(key)]
            key_index += 1
        else:
            key_repeated += char

    # Decrypt
    plaintext = ''
    for c, k in zip(ciphertext, key_repeated):
        if c.isalpha():
            # Reverse Vigenere shift: (ciphertext index - key index) mod 26
            c_index = ord(c) - ord('A')
            k_index = ord(k) - ord('A')
            p_index = (c_index - k_index) % 26
            plaintext += chr(p_index + ord('A'))
        else:
            plaintext += c

    print(f"Key (repeated): {key_repeated}")
    print(f"Plaintext:     {plaintext}")

    again = input("\nDo another operation? (Y/N): ").strip().upper()
    if again != 'Y':
        return False  # Signal to exit
    return True  # Signal to continue


def analyze_key_strength(key):
    """Analyze and display key strength"""
    key = ''.join(c for c in key.upper() if c.isalpha())
    length = len(key)
    unique_chars = len(set(key))

    print(f"\nKey Analysis:")
    print(f"Length: {length} characters")
    print(f"Unique letters: {unique_chars}")

    if length < 5:
        strength = "WEAK"
    elif length < 8:
        strength = "MODERATE"
    else:
        strength = "STRONG"

    print(f"Strength: {strength}")

    if length < 8:
        print("Recommendation: Use a key with at least 8 characters.")

def display_menu():
    """Display main menu"""
    print("\n" + "="*50)
    print("    VIGENÈRE CIPHER ENCRYPTION SYSTEM")
    print("="*50)
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Exit")
    print("="*50)


if __name__ == "__main__":
    print("Welcome to Vigenère Cipher System!")

    while True:
        display_menu()
        choice = input("\nEnter your choice (1-3): ").strip()

        try:
            if choice == '1':
                continue_program = vigenere_encrypt()
                if not continue_program:
                    print("Exiting program.")
                    break
            elif choice == '2':
                continue_program = vigenere_decrypt()
                if not continue_program:
                    print("Exiting program.")
                    break
            elif choice == '3':
                print("\nThank you for using Vigenère Cipher System!")
                break
            else:
                print("❌ Invalid choice. Please select 1-3.")
        except Exception as e:
            print(f"❌ Error: {e}")
