def vigenere_encrypt(plaintext, key): 
    """
    Encrypts the plaintext using the Vigenere Cipher with the given key.
    
    Args:
        plaintext (str): The text to be encrypted (case-insensitive, non-letters unchanged).
        key (str): The keyword (case-insensitive).
    
    Returns:
        str: The encrypted ciphertext.
    """
    # Convert to uppercase
    plaintext = plaintext.upper()
    key = key.upper()
    
    # Remove non-alphabetic characters from key
    key = ''.join(c for c in key if c.isalpha())
    
    #safe guard for empty key
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")
    
    # Repeat key to match plaintext length (ignoring non-letters)
    key_repeated = ''
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            key_repeated += key[key_index % len(key)]
            key_index += 1
        else:
            key_repeated += char  # Keep non-letters unchanged
    
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
    
    if not key:
        raise ValueError("Key must contain at least one alphabetic character.")
    
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

# ... (rest of the code remains the same)

if __name__ == "__main__":
    while True:
        choice = input("Choose operation: (E)ncrypt or (D)ecrypt: ").strip().upper()
        
        if choice == 'E':
            plaintext = input("Enter the plaintext: ")
            key = input("Enter the key: ")
            encrypted = vigenere_encrypt(plaintext, key)
            print(f"Encrypted: {encrypted}")
        elif choice == 'D':
            ciphertext = input("Enter the ciphertext: ")
            key = input("Enter the key: ")
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