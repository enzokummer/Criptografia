import AES, hashlib

string_input = "Bom dia, Gondim!"
hash_input = hashlib.md5(string_input.encode())

print(string_input)
print(f"O hash de 128 bits da {hash_input.hexdigest()}")