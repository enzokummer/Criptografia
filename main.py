import sys, os
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
from AES import AES


def process_text_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def process_image_file(file_path):
    with Image.open(file_path) as img:
        img = img.convert('RGB')
        width, height = img.size
        byte_data = bytearray(img.tobytes())
    return bytes(byte_data), width, height

def save_encrypted_data(data, file_path):
    dir_name, base_name = os.path.split(file_path)
    new_file_name = 'encrypted_' + base_name
    new_file_path = os.path.join(dir_name, new_file_name)
    with open(new_file_path, 'wb') as file:
        file.write(data)

def save_decrypted_data(decrypted_data, file_path, width=None, height=None):
    dir_name, base_name = os.path.split(file_path)
    new_file_name = 'decrypted_' + base_name
    new_file_path = os.path.join(dir_name, new_file_name)
    with open(new_file_path, 'wb') as file:
        file.write(decrypted_data)

    if width and height:
        img = Image.frombytes('RGB', (width, height), decrypted_data)
        img.save(new_file_path)
    else:
        encodings = ['utf-8', 'ascii', 'latin-1']
        for encoding in encodings:
            try:
                with open(new_file_path, 'r', encoding=encoding) as file:
                    print(f"Conteúdo descriptografado ({encoding}):\n{file.read()}")
                break
            except UnicodeDecodeError:
                if encoding == encodings[-1]:
                    print(f"O arquivo descriptografado não pôde ser lido como texto usando as codificações: {', '.join(encodings)}")

def render_encrypted_image(encrypted_file_path, output_image_path, width, height):
    # Ler os dados criptografados
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    # Converte os bytes em um array NumPy
    data_array = np.frombuffer(encrypted_data, dtype=np.uint8)

    # Reshape o array para as dimensões da imagem
    # Se o arquivo criptografado não tiver exatamente o tamanho esperado, isso pode causar problemas
    try:
        image_array = data_array[:width*height*3].reshape((height, width, 3))
    except ValueError:
        print("Erro: Os dados não correspondem às dimensões fornecidas.")
        return

    # Cria uma imagem a partir do array
    img = Image.fromarray(image_array)

    # Salva a imagem
    img.save(output_image_path)

    # Exibe a imagem
    plt.imshow(img)
    plt.axis('off')
    plt.show()

def main():
    if len(sys.argv) != 3:
        print("Uso correto: python main.py <caminho_para_arquivo> <numero de rodadas>")
        sys.exit(1)

    file_path = sys.argv[1]
    num_rounds = int(sys.argv[2])

    if file_path.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp', '.gif')):
        data, width, height = process_image_file(file_path)

        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\xcf\x4f\x3c\x1e\xfb\x15'
        iv = os.urandom(16)
        print(f"IV gerado: {iv.hex()}")

        aes = AES(key, num_rounds)

        encrypted_data = aes.encrypt_ctr(data, iv)
        save_encrypted_data(encrypted_data, file_path)

        decrypted_data = aes.decrypt_ctr(encrypted_data, iv)
        save_decrypted_data(decrypted_data, file_path, width, height)
        dir_name, base_name = os.path.split(file_path)

        path_imagem_criptografada = os.path.join(dir_name, f'encrypted_{base_name}')
        path_imagem_renderizada = 'criptografada_renderizada.png'
        render_encrypted_image(path_imagem_criptografada, path_imagem_renderizada, width, height)

        print(f"Imagem criptografada salva como 'encrypted_{file_path}'")
        print("Renderizamos a imagem criptografada e a salvamos.")
        print(f"Imagem descriptografada salva como 'decrypted_{file_path}'")
            
    else:
        data = process_text_file(file_path)
        print(f"Texto original: {data}")

        key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\xcf\x4f\x3c\x1e\xfb\x15'
        iv = os.urandom(16)
        print(f"IV gerado: {iv.hex()}")
        
        aes = AES(key, num_rounds)

        encrypted_data = aes.encrypt_ctr(data, iv)
       
        save_encrypted_data(encrypted_data, file_path)

        decrypted_data = aes.decrypt_ctr(encrypted_data, iv)
        
        save_decrypted_data(decrypted_data, file_path)

        print(f"Arquivo criptografado salvo como 'encrypted_{file_path}'")
        print(f"Arquivo descriptografado salvo como 'decrypted_{file_path}'")

if __name__ == '__main__':
    main()
