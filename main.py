import sys,os
from PIL import Image
from AES import AES, pad, unpad

def process_text_file(file_path):
    """Lê um arquivo de texto e converte o conteúdo em bytes."""
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    return content.encode('utf-8')

def process_image_file(file_path):
    """Lê uma imagem e converte o conteúdo em bytes."""
    with Image.open(file_path) as img:
        img = img.convert('RGB')
        byte_data = bytearray(img.tobytes())
    return bytes(byte_data)

def save_encrypted_data(data, file_path):
    # Separa o caminho e o nome do arquivo
    dir_name, base_name = os.path.split(file_path)
    
    # Adiciona o prefixo ao nome do arquivo
    new_file_name = 'encrypted_' + base_name
    
    # Combina novamente o caminho com o novo nome do arquivo
    new_file_path = os.path.join(dir_name, new_file_name)
    
    # Salva os dados criptografados no novo arquivo
    with open(new_file_path, 'wb') as file:
        file.write(data)

def save_decrypted_data(decrypted_data, file_path):
    """Salva os dados descriptografados em um arquivo."""
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
        # Se o arquivo original for uma imagem, salve como imagem
        img = Image.frombytes('RGB', (width, height), decrypted_data)
        img.save(file_path)
    else:
        # Assume que é um arquivo de texto
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(decrypted_data.decode('utf-8'))

def main():
    if len(sys.argv) != 2:
        print("Uso correto: python main.py <caminho_para_arquivo>")
        sys.exit(1)

    file_path = sys.argv[1]

    # Carrega e processa o arquivo de entrada
    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
        # Processa como uma imagem
        data = process_image_file(file_path)
    else:
        # Assume que é um arquivo de texto
        data = process_text_file(file_path)

    # Chave e IV para AES
    key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\xcf\x4f\x3c\x1e\xfb\x15'  # Exemplo de chave de 16 bytes
    iv = b'\x00' * 16  # IV de 16 bytes inicializado com zeros

    # Cria uma instância do AES com a chave
    aes = AES(key)

    # Criptografa os dados
    encrypted_data = aes.encrypt_ctr(data, iv)

    # Salva os dados criptografados em um novo arquivo
    save_encrypted_data(encrypted_data, file_path)

    # Descriptografa os dados para verificação
    decrypted_data = aes.decrypt_ctr(encrypted_data, iv)

    # Salva os dados descriptografados em um novo arquivo
    save_decrypted_data(decrypted_data, file_path)

    print(f"Arquivo criptografado salvo como 'encrypted_{file_path}'")
    print(f"Arquivo descriptografado salvo como 'decrypted_{file_path}'")

if __name__ == '__main__':
    main()