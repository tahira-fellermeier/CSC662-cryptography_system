def vigenere_encrypt(plaintext, key):
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
    
    return ciphertext

def vigenere_decrypt(ciphertext, key):
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
    
    return plaintext

if __name__ == "__main__":
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
                continue_program = vigenere_encrypt()
                if not continue_program:
                    print("Exiting program.")
                    break
            elif choice == '3':
                print("\nThank you for using Vigenère Cipher System!")
                break
            else:
                print("❌ Invalid choice. Please select 1-5.")
        except Exception as e:
            print(f"❌ Error: {e}")