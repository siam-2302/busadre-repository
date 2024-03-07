import streamlit as st

st.header("XOR Cipher")

plaintext = bytes(st.text_input("Plain Text:").encode())
key = bytes(st.text_input("Key:").encode())

def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    
    for i in range(len(plaintext)):
       # plaintext_byte = plaintext[i]
      #  key_byte = key[i % len(key)]
        ciphertext.append(plaintext[i] ^ key[i % len(key)])
        st.write(f"Plaintext byte: {plaintext[i]:08b} = {chr(plaintext[i])}")
        st.write(f"Key byte:       {key [i % len(key)]:08b} = {chr(key[i % len (key)])}")
        st.write(f"XOR result:     {ciphertext[-1]:08b} = {chr(ciphertext[-1])}")
        st.write("--------------------")       

    return ciphertext  

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
    return xor_encrypt(ciphertext, key) # XOR decryption is the same as encryption 

if st.button("Submit"): 
    if not key:
        st.error("Invalid key")
    else:
        if not(1 < len(plaintext) >= len(key)>=1):
            st.write("Plaintext length should be equal or greater than the length of key")
        elif not plaintext != key: 
            st.write("Plaintext should not be equal to the key")
    
        else: 
            cipher_text = xor_encrypt(plaintext, key)
            st.write("Ciphertext:", cipher_text.decode())
    
            decryption =  xor_decrypt(cipher_text, key)
            st.write("Decrypted:", decryption.decode())
