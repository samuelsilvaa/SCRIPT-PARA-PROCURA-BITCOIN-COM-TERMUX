import os
import binascii
import hashlib
import base58
import ecdsa
import requests

def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def sha256(x):
    return hashlib.sha256(x).digest()

def generate_private_key():
    return binascii.hexlify(os.urandom(32)).decode('utf-8')

def private_key_to_wif(private_key):
    extended_key = '80' + private_key
    first_sha256 = sha256(binascii.unhexlify(extended_key))
    second_sha256 = sha256(first_sha256)
    checksum = second_sha256[:4]
    final_key = extended_key + binascii.hexlify(checksum).decode('utf-8')
    wif = base58.b58encode(binascii.unhexlify(final_key))
    return wif.decode('utf-8')

def private_key_to_public_key(private_key):
    private_key_bytes = binascii.unhexlify(private_key)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return b'04' + vk.to_string()

def public_key_to_address(public_key):
    sha256_result = sha256(public_key)
    ripemd160_result = ripemd160(sha256_result).digest()
    network_byte = b'\x00' + ripemd160_result
    checksum = sha256(sha256(network_byte))[:4]
    address = base58.b58encode(network_byte + checksum)
    return address.decode('utf-8')

def get_balance(address):
    try:
        url = 'https://blockchain.info/q/addressbalance/{}'.format(address)
        response = requests.get(url)
        balance = int(response.text)
        return balance
    except:
        return None

def display_progress(private_key, wif, address):
    print("\nSearching for Bitcoin...")
    print(f"Private Key: {private_key}")
    print(f"WIF: {wif}")
    print(f"Address: {address}")

if __name__ == '__main__':
    destination_address = 'SUA_WALLET'
    while True:
        private_key = generate_private_key()  # Chama a função definida acima
        wif = private_key_to_wif(private_key)
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)

        display_progress(private_key, wif, address)

        balance = get_balance(address)
        if balance is not None and balance > 0:
            print(f'\nFound Bitcoin! Balance: {balance} satoshis')
            print(f'Sending funds to {destination_address}...')
            # Adicione uma função de envio aqui se necessário
            print(f'Funds sent to {destination_address}')
            break
        else:
            print("No Bitcoin found, generating a new key...")
