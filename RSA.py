import os
import random
import base64
from hashlib import sha3_512


#Teste de primalidade de Miller-Rabun
def millerRabin(number, k):
    if number == 2:
        return True
    if number % 2 == 0: # Se o number for par ele e composto
        return False

    r, s = 0, number - 1

    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, number - 1)
        x = pow(a, s, number)
        if x == 1 or x == number - 1:
            continue
        for _ in range(r-1):
            x = pow(x, 2, number)
            if x == 1 or x == number - 1:
                break
        else:
            return False
    return True

#Gera um numero primo com um numero minimo de bits
def generate_prime(min_bits):
    while True:
        extra_bits = random.randint(0,1) ########################################################################
        prime = random.getrandbits(min_bits + extra_bits)

        prime |= (1 << (min_bits - 1))
        prime |= 1

        if millerRabin(prime, 40):
            return prime

#Calcula o inverso modular de e mod phi
def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = extended_gcd(b % a, a)
            return gcd, y - (b // a) * x, x

    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError("modulo inverso não existe")
    else:
        return x % phi

#Funcao de geracao de mascara
def mgf1(seed, length):
    t = b""
    hLen = sha3_512().digest_size
    for counter in range(0, (length + hLen - 1) // hLen):
        c = counter.to_bytes(4, 'big')
        t += sha3_512(seed + c).digest()
    return t[:length]

#Faz xor bit a bit
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

#Faz o padding OAEP
def oaep_pad(message, n_len):
    k = n_len // 8
    mLen = len(message)
    hLen = sha3_512().digest_size

    if mLen > k - 2 * hLen - 2:
        raise ValueError(f"Mensagem muito longa. Máximo permitido: {k - 2 * hLen - 2} bytes")

    lHash = sha3_512(b"").digest()

    PS = b'\x00' * (k - mLen - 2 * hLen - 2)
    DB = lHash + PS + b'\x01' + message

    seed = os.urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1)
    maskedDB = xor_bytes(DB, dbMask)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = xor_bytes(seed, seedMask)

    return b'\x00' + maskedSeed + maskedDB

#Remove o padding OAEP
def oaep_unpad(padded_message):
    hLen = sha3_512().digest_size

    if len(padded_message) < 2 * hLen + 2:
        raise ValueError("Mensagem padded muito curta")

    maskedSeed = padded_message[1:1 + hLen]
    maskedDB = padded_message[1 + hLen:]
    seedMask = mgf1(maskedDB, hLen)
    seed = xor_bytes(maskedSeed, seedMask)
    dbMask = mgf1(seed, len(maskedDB))
    DB = xor_bytes(maskedDB, dbMask)

    lHash = DB[:hLen]

    if lHash != sha3_512(b"").digest():
        raise ValueError("lHash não corresponde")

    i = hLen

    while i < len(DB):
        if DB[i] == 1:
            i += 1
            break
        elif DB[i] != 0:
            raise ValueError(f"Byte inválido encontrado: {DB[i]} na posição {i}")
        i += 1

    if i == len(DB):
        raise ValueError("Byte separador 0x01 não encontrado")

    return DB[i:]

#Decripta e chama o unpad
def decrypt_and_unpad(ciphertext, d, n):
    decrypted = pow(ciphertext, d, n)
    padded_message = decrypted.to_bytes((n.bit_length() + 7) // 8, 'big')

    # Remove o byte inicial se necessário
    if len(padded_message) > n.bit_length() // 8:
        padded_message = padded_message[1:]

    return oaep_unpad(padded_message)

#Assina a mensagem
def sign_message(message, d, n):
    # Calcula o hash da mensagem
    hash_object = sha3_512(message)
    message_hash = hash_object.digest()

    #Converte o hash para inteiro
    hash_int = int.from_bytes(message_hash, 'big')

    #Assina o hash (encripta com a chave privada)
    signature = pow(hash_int, d, n)

    return signature

#Verifica a assinatura
def verify_signature(message, signature, e, n):
    # Calcula o hash da mensagem
    hash_object = sha3_512(message)
    message_hash = hash_object.digest()

    #Converte o hash para inteiro
    hash_int = int.from_bytes(message_hash, 'big')

    #Decripta a assinatura (e verifica com a chave publica)
    decrypted_hash = pow(signature, e, n)

    #Compara o hash decriptado com o calculado
    return decrypted_hash == hash_int

#Formata a mensagem assinada
def format_signed_message(message, signature):
    #Converte a mensagem e a assinatura pra base64
    message_b64 = base64.b64encode(message).decode('utf-8')
    signature_b64 = base64.b64encode(signature.to_bytes((signature.bit_length() + 7) // 8, 'big')).decode('utf-8')

    #Formata o resultado
    formatted_message = f"-----BEGIN SIGNED MESSAGE-----\n{message_b64}\n-----BEGIN SIGNATURE-----\n{signature_b64}\n-----END SIGNED MESSAGE-----"

    return formatted_message

#Faz o parsing da mensagem assinada
def parse_signed_message(formatted_message):
    #Divide a mensagem em linhas
    lines = formatted_message.strip().split('\n')

    #Inicializa as variáveis
    message_b64 = ""
    signature_b64 = ""
    current_section = None

    #Itera sobre as linhas pra extrair a mensagem e a assinatura
    for line in lines:
        if line.startswith("-----BEGIN SIGNED MESSAGE-----"):
            current_section = "message"
        elif line.startswith("-----BEGIN SIGNATURE-----"):
            current_section = "signature"
        elif line.startswith("-----END SIGNED MESSAGE-----"):
            break
        elif current_section == "message" and line.strip():
            message_b64 += line.strip()
        elif current_section == "signature" and line.strip():
            signature_b64 += line.strip()

    #Verifica se tanto a mensagem quanto a assinatura foram encontradas
    if not message_b64 or not signature_b64:
        raise ValueError("Formato de mensagem assinada inválido")

    #Decodifica a mensagem e a assinatura
    message = base64.b64decode(message_b64)
    signature = int.from_bytes(base64.b64decode(signature_b64), 'big')

    return message, signature

#Geracao de chaves
def generate_keys():
    min_bits = 1024
    p = generate_prime(min_bits)
    q = generate_prime(min_bits)
    while p == q:
        q = generate_prime(min_bits)

    #Calculo do n e do phi(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)

    e = 65537  # Bom vavlor e comum para e
    d = mod_inverse(e, phi_n)

    return (e, n), (d, n)

#Encripta a mensagem
def encrypt_message(message, public_key):
    e, n = public_key
    n_len = n.bit_length()
    padded_message = oaep_pad(message.encode(), n_len)
    ciphertext = pow(int.from_bytes(padded_message, 'big'), e, n)
    return ciphertext

#Decripta a mensagem
def decrypt_message(ciphertext, private_key):
    d, n = private_key
    decrypted_message = decrypt_and_unpad(ciphertext, d, n)
    return decrypted_message.decode()

#Assina e formata a mensagem
def sign_and_format(message, private_key):
    d, n = private_key
    signature = sign_message(message.encode(), d, n)
    return format_signed_message(message.encode(), signature)

#Verifica a mensagem assinada
def verify_signed_message(formatted_message, public_key):
    e, n = public_key
    message, signature = parse_signed_message(formatted_message)
    return verify_signature(message, signature, e, n), message.decode()

def encrypt_file(file_path, public_key):
    e, n = public_key
    n_len = n.bit_length()
    max_bytes = n_len // 8 - 2 * sha3_512().digest_size - 2

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    encrypted_blocks = []
    for i in range(0, len(plaintext), max_bytes):
        block = plaintext[i:i+max_bytes]
        padded_block = oaep_pad(block, n_len)
        encrypted_block = pow(int.from_bytes(padded_block, 'big'), e, n)
        encrypted_blocks.append(encrypted_block)

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        for block in encrypted_blocks:
            file.write(block.to_bytes((n_len + 7) // 8, 'big'))

    return encrypted_file_path

def decrypt_file(file_path, private_key):
    d, n = private_key
    n_len = n.bit_length()
    block_size = (n_len + 7) // 8

    with open(file_path, 'rb') as file:
        ciphertext = file.read()

    decrypted_blocks = []
    for i in range(0, len(ciphertext), block_size):
        block = int.from_bytes(ciphertext[i:i+block_size], 'big')
        decrypted_block = decrypt_and_unpad(block, d, n)
        decrypted_blocks.append(decrypted_block)

    decrypted_file_path = file_path[:-4] if file_path.endswith('.enc') else file_path + '.dec'
    with open(decrypted_file_path, 'wb') as file:
        for block in decrypted_blocks:
            file.write(block)

    return decrypted_file_path


def sign_file(file_path, private_key):
    d, n = private_key
    with open(file_path, 'rb') as file:
        content = file.read()

    # Calcula o hash SHA-3 do conteúdo do arquivo
    hash_object = sha3_512(content)
    file_hash = hash_object.digest()

    # Assina o hash (criptografa com a chave privada)
    signature = pow(int.from_bytes(file_hash, 'big'), d, n)

    # Cria um arquivo de assinatura
    signature_file_path = file_path + '.sig'
    with open(signature_file_path, 'wb') as sig_file:
        sig_file.write(signature.to_bytes((n.bit_length() + 7) // 8, 'big'))

    return signature_file_path

def verify_file_signature(file_path, signature_file_path, public_key):
    e, n = public_key

    # Lê o arquivo original
    with open(file_path, 'rb') as file:
        content = file.read()

    # Calcula o hash SHA-3 do conteúdo do arquivo
    hash_object = sha3_512(content)
    file_hash = hash_object.digest()

    # Lê a assinatura
    with open(signature_file_path, 'rb') as sig_file:
        signature = int.from_bytes(sig_file.read(), 'big')

    # Verifica a assinatura (descriptografa com a chave pública)
    decrypted_hash = pow(signature, e, n)

    # Compara o hash descriptografado com o hash calculado
    return decrypted_hash == int.from_bytes(file_hash, 'big')

#Funcao principal do codigo
def main():
    public_key, private_key = generate_keys()
    print("Chaves geradas com sucesso.")
    print("Chave Publica:", public_key)
    print("Chave Privada:", private_key)

    while True:
        print("\nEscolha uma opção:")
        print("1. Cifrar mensagem")
        print("2. Decifrar mensagem")
        print("3. Assinar mensagem")
        print("4. Verificar assinatura")
        print("5. Cifrar arquivo")
        print("6. Decifrar arquivo")
        print("7. Assinar arquivo")
        print("8. Verificar assinatura de arquivo")
        print("9. Sair")

        choice = input("Digite o número da opção desejada: ")

        if choice == '1':
            message = input("Digite a mensagem a ser cifrada: ")
            ciphertext = encrypt_message(message, public_key)
            print(f"Mensagem cifrada: {ciphertext}")

        elif choice == '2':
            ciphertext = int(input("Digite o texto cifrado (número inteiro): "))
            decrypted_message = decrypt_message(ciphertext, private_key)
            print(f"Mensagem decifrada: {decrypted_message}")

        elif choice == '3':
            message = input("Digite a mensagem a ser assinada: ")
            signed_message = sign_and_format(message, private_key)
            print("Mensagem assinada:")
            print(signed_message)


        elif choice == '4':
            print("Cole a mensagem assinada (incluindo cabeçalhos). Pressione Enter duas vezes quando terminar:")

            signed_message_lines = []

            while True:
                line = input()
                if line.strip() == "":
                    break
                signed_message_lines.append(line)

            signed_message = "\n".join(signed_message_lines)

            try:
                is_valid, original_message = verify_signed_message(signed_message, public_key)
                if is_valid:
                    print("Assinatura válida!")
                    print(f"Mensagem original: {original_message}")

                else:
                    print("Assinatura inválida!")

            except ValueError as e:
                print(f"Erro ao verificar a assinatura: {str(e)}")

            except Exception as e:
                print(f"Ocorreu um erro inesperado: {str(e)}")


        elif choice == '5':
            file_path = input("Digite o caminho do arquivo a ser cifrado: ")

            try:
                encrypted_file_path = encrypt_file(file_path, public_key)
                print(f"Arquivo cifrado salvo em: {encrypted_file_path}")

            except Exception as e:
                print(f"Erro ao cifrar o arquivo: {str(e)}")


        elif choice == '6':
            file_path = input("Digite o caminho do arquivo a ser decifrado: ")

            try:
                decrypted_file_path = decrypt_file(file_path, private_key)
                print(f"Arquivo decifrado salvo em: {decrypted_file_path}")

            except Exception as e:
                print(f"Erro ao decifrar o arquivo: {str(e)}")



        elif choice == '7':
            file_path = input("Digite o caminho do arquivo a ser assinado: ")

            try:
                signature_file_path = sign_file(file_path, private_key)
                print(f"Arquivo de assinatura salvo em: {signature_file_path}")

            except Exception as e:
                print(f"Erro ao assinar o arquivo: {str(e)}")


        elif choice == '8':
            file_path = input("Digite o caminho do arquivo original: ")
            signature_file_path = input("Digite o caminho do arquivo de assinatura: ")

            try:
                is_valid = verify_file_signature(file_path, signature_file_path, public_key)

                if is_valid:
                    print("Assinatura válida! O arquivo não foi modificado.")

                else:
                    print("Assinatura inválida! O arquivo pode ter sido modificado.")

            except Exception as e:
                print(f"Erro ao verificar a assinatura do arquivo: {str(e)}")

        elif choice == '9':
            print("Encerrando o programa.")
            break

        else:

            print("Opção inválida. Por favor, tente novamente.")
if __name__ == "__main__":
    main()