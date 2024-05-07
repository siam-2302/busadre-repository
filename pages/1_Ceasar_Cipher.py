import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    result = ""

    if len(shift_keys) <= 1 or len(shift_keys) > len(text):
        raise ValueError("Invalid shift keys length")

    for i, char in enumerate(text):
        shift_key = shift_keys[i % len(shift_keys)]

        if 32 <= ord(char) <= 125:
            new_ascii = ord(char) + shift_key if not ifdecrypt else ord(char) - shift_key
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
            result += chr(new_ascii)
        else:
            result += char
    return result

st.title("Text Encryption and Decryption")

text_input = st.text_input("Enter text:")
shift_keys_input = st.text_input("Enter shift keys (separated by spaces):")

if st.button("Submit"):
    shift_keys = [int(key) for key in shift_keys_input.split()]
    encrypted_text = encrypt_decrypt(text_input, shift_keys, False)
    decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, True)

    st.write("Original text:", text_input)
    st.write("Shift keys:", shift_keys)
    st.write("Encrypted text:", encrypted_text)
    st.write("Decrypted text:", decrypted_text)
