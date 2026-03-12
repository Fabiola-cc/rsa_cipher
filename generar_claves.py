from Crypto.PublicKey import RSA

def generar_par_claves(bits: int = 3072, pwd: str = b""):
    if (bits not in [3072, 2048]):
        print("El valor dado para bits de la clave debe ser 3072 (recomendado) o 2048")
        print("Valor recibido: ", bits)
        return

    key = RSA.generate(bits)
    
    # Exportar clave privada PEM
    with open("claves_rsa/private_key.pem", "wb") as f:
        private_key = key.export_key(passphrase=pwd,
                                    pkcs=8,
                                    protection='PBKDF2WithHMAC-SHA512AndAES256-CBC',
                                    prot_params={'iteration_count':131072})
        f.write(private_key)

    # Exportar clave pública PEM
    public_key = key.publickey().export_key(format='PEM')
    with open("claves_rsa/public_key.pem", "wb") as f:
        f.write(public_key)
    
    print("Claves generadas en la carpeta 'claves_rsa': private_key.pem y public_key.pem")

if __name__ == '__main__':
    private_key_pwd = b"lab04uvg"
    generar_par_claves(3072, private_key_pwd)

    # Ejemplo de lectura
    # pwd = b'secret'
    # with open("claves_rsa/private_key.pem", "rb") as f:
    #     data = f.read()
    #     mykey = RSA.import_key(data, pwd)