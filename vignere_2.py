def vigenere_encrypt():
    """
    Encrypts the plaintext using the Vigenere Cipher with the given key.
    
    Args:
    plaintext (str): The text to encrypt (case-insensitive, non-letters unchanged).
    key (str): The keyword (case-insensitive).
    
    Returns:
    str: The encrypted ciphertext.
    """
    # Convert to uppercase and prepare key
    plaintext = plaintext.upper()
    key = key.upper()
    
    # Remove non-alphabetic characters from key for simplicity
    key = ''.join(c for c in key if c.isalpha())

    # Encryption with step-by-step display
    print(f"\nPlaintext: {plaintext}")
    print(f"Key: {key}")
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
        print(f"Ciphertext: {ciphertext}")

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
    # Convert to uppercase and prepare key
    ciphertext = ciphertext.upper()
    key = key.upper()
    
    # Remove non-alphabetic characters from key
    key = ''.join(c for c in key if c.isalpha())

    # Decryption step-by-step display
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

if __name__ == "__main__":
    while True:
        choice = input("Choose operation: (E)ncrypt or (D)ecrypt: ").strip().upper()
        
        if choice == 'E':
            # Prompt for plaintext until non-empty
            plaintext = ""
            while not plaintext:
                plaintext = input("Enter the plaintext: ").strip()
                if not plaintext:
                    print("Plaintext cannot be empty. Please try again.")
            
            # Prompt for key until valid (contains at least one letter)
            key = ""
            while not key or not any(c.isalpha() for c in key):
                key = input("Enter the key: ").strip()
                if not key:
                    print("Key cannot be empty. Please try again.")
                elif not any(c.isalpha() for c in key):
                    print("Key must contain at least one letter. Please try again.")
            
            encrypted = vigenere_encrypt(plaintext, key)
            print(f"Encrypted: {encrypted}")
        
        elif choice == 'D':
            # Prompt for ciphertext until non-empty
            ciphertext = ""
            while not ciphertext:
                ciphertext = input("Enter the ciphertext: ").strip()
                if not ciphertext:
                    print("Ciphertext cannot be empty. Please try again.")
            
            # Prompt for key until valid (contains at least one letter)
            key = ""
            while not key or not any(c.isalpha() for c in key):
                key = input("Enter the key: ").strip()
                if not key:
                    print("Key cannot be empty. Please try again.")
                elif not any(c.isalpha() for c in key):
                    print("Key must contain at least one letter. Please try again.")
            
            decrypted = vigenere_decrypt(ciphertext, key)
            print(f"Decrypted: {decrypted}")
        
        else:
            print("Invalid choice. Please enter 'E' for encrypt or 'D' for decrypt.")
            continue  # Skip to next iteration if invalid
        
        # Ask if user wants to do another operation
        again = input("Do another operation? (Y/N): ").strip().upper()
        if again != 'Y':
            print("Exiting program.")
            break