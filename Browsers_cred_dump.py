import os
import sqlite3
import json
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import binascii
import shutil
import win32crypt
import hmac
import sys
from base64 import b64decode
from pyasn1.codec.der import decoder
from os import path
from re import compile
from sqlite3 import connect
from hashlib import sha1, pbkdf2_hmac
from binascii import unhexlify
from io import BufferedReader, BytesIO
from tempfile import NamedTemporaryFile
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes


url_clean = compile(r"https?://(www\.)?")

def decryptmoz3des(global_salt: bytes, master_password: bytes, entry_salt: bytes, encrypted_data: bytes) -> bytes:
    chp = sha1(global_salt + master_password).digest() + entry_salt
    pes = entry_salt.ljust(20, b'\x00')
    k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
    k2 = hmac.new(chp, pes + hmac.new(chp, pes, sha1).digest(), sha1).digest()
    key_iv = k1 + k2
    return DES3.new(key_iv[:24], DES3.MODE_CBC, key_iv[-8:]).decrypt(encrypted_data)

def get_decoded_login_data(logins_file: str) -> list:
    def decode_login_data(data: bytes) -> tuple:
        asn1data = decoder.decode(b64decode(data))
        key_id = asn1data[0][0].asOctets()
        iv = asn1data[0][1][1].asOctets()
        ciphertext = asn1data[0][2].asOctets()
        return key_id, iv, ciphertext

    logins = []

    if isinstance(logins_file, str) and logins_file.endswith('logins.json'):
        with open(logins_file, 'r') as loginf:
            json_logins = json.load(loginf)

        if 'logins' in json_logins:
            for row in json_logins['logins']:
                enc_username = row['encryptedUsername']
                enc_password = row['encryptedPassword']
                logins.append((decode_login_data(enc_username), decode_login_data(enc_password), row['hostname']))

    return logins

CKA_ID = unhexlify('f8{}1'.format('0' * 29))

def extract_secret_key(master_password, key_data) -> bytes:
    def decode_data(data):
        return decoder.decode(data)[0]

    pwd_check, global_salt = key_data[b'password-check'], key_data[b'global-salt']
    entry_salt = pwd_check[3:3 + pwd_check[1]]
    encrypted_passwd = pwd_check[-16:]
    cleartext_data = decryptmoz3des(global_salt, master_password, entry_salt, encrypted_passwd)

    if cleartext_data != b'password-check\x02\x02': raise Exception(
        "password check error, Master Password is certainly used")
    if CKA_ID not in key_data: return b''

    priv_key_entry = key_data[CKA_ID]
    salt_len, name_len = priv_key_entry[1], priv_key_entry[2]
    data = priv_key_entry[3 + salt_len + name_len:]
    entry_salt, priv_key_data = decode_data(data)[0][0][1][0].as_octets(), decode_data(data)[0][1].as_octets()
    priv_key = decryptmoz3des(global_salt, master_password, entry_salt, priv_key_data)
    key = long_to_bytes(decode_data(decode_data(priv_key)[0][2].as_octets())[0][3])

    return key

def decryptPBE(decodedItem, masterPassword, globalSalt) -> tuple:
    pbeAlgo = str(decodedItem[0][0][0])
    if pbeAlgo == '1.2.840.113549.1.5.13':
        assert str(decodedItem[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
        assert str(decodedItem[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
        assert str(decodedItem[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
        entrySalt = decodedItem[0][0][1][0][1][0].asOctets()
        iterationCount = int(decodedItem[0][0][1][0][1][1])
        keyLength = int(decodedItem[0][0][1][0][1][2])
        assert keyLength == 32
        k = sha1(globalSalt + masterPassword).digest()
        key = pbkdf2_hmac('sha256', k, entrySalt, iterationCount, dklen=keyLength)
        iv = b'\x04\x0e' + decodedItem[0][0][1][1][1].asOctets()
        cipherT = decodedItem[0][1].asOctets()
        clearText = AES.new(key, AES.MODE_CBC, iv).decrypt(cipherT)

        return clearText, pbeAlgo

def getKey(masterPassword: bytes, keydb: str) -> tuple:
    if isinstance(keydb, (BufferedReader, BytesIO)):
        with NamedTemporaryFile(prefix="firefox_", suffix=".key4.db", delete=False) as tmp:
            keydb.seek(0)
            tmp.write(keydb.read())
            keydb = tmp.name

    if keydb.endswith('key4.db'):
        with connect(keydb) as conn:
            c = conn.cursor()
            c.execute("SELECT item1,item2 FROM metadata WHERE id='password';")
            globalSalt, item2 = c.fetchone()
            decodedItem2 = decoder.decode(item2)
            clearText, algo = decryptPBE(decodedItem2, masterPassword, globalSalt)

            if clearText == b'password-check\x02\x02':
                c.execute("SELECT a11,a102 FROM nssPrivate;")
                a11, a102 = next((row for row in c if row[0] is not None), (None, None))

                if a102 == CKA_ID:
                    decoded_a11 = decoder.decode(a11)
                    clearText, algo = decryptPBE(decoded_a11, masterPassword, globalSalt)

                    return clearText[:24], algo

    return None, None

def DecryptLogins(loginsFile: str, keydbFile: str, masterPassword="") -> list:
    def decrypt3DES(encryptedData: bytes, key: bytes, iv: bytes) -> str:
        decrypted = unpad(DES3.new(key, DES3.MODE_CBC, iv).decrypt(encryptedData), 8)
        return decrypted.decode(errors='ignore')

    if not path.exists(loginsFile) or not path.exists(keydbFile):
        raise FileNotFoundError("Either logins.json or key4.db file does not exist!")

    key, algo = getKey(masterPassword.encode(), keydbFile)
    if key is None:
        raise Exception("Unable to retrieve key")

    logins = get_decoded_login_data(loginsFile)
    credentials = []
    supported_algorithms = ['1.2.840.113549.1.12.5.1.3', '1.2.840.113549.1.5.13']

    if algo in supported_algorithms:
        for i in logins:
            assert i[0][0] == CKA_ID
            hostname = url_clean.sub('', i[2]).strip().strip('/')
            username = decrypt3DES(i[0][2], key, i[0][1])
            password = decrypt3DES(i[1][2], key, i[1][1])
            credentials.append({
                "url": hostname,
                "username": username,
                "password": password
            })

    return credentials


def get_browser_key(local_state_path):
    """Extract decryption key for Chrome or Brave."""
    try:
        with open(local_state_path, 'r', encoding='utf-8') as file:
            local_state = json.load(file)

        encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        encrypted_key = encrypted_key[5:]  # Remove the 'DPAPI' prefix
        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return key
    except Exception as e:
        print(f"Error getting key from {local_state_path}: {e}")
        return None

def decrypt_password(ciphertext, key):
    """Decrypt the password using the AES algorithm."""
    try:
        iv = ciphertext[3:15]
        payload = ciphertext[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)[:-16].decode()  # Remove the suffix (16 bytes)
        return decrypted_pass
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return ""

def extract_chrome_passwords(dump_path):
    """Extract passwords from Chrome's 'Login Data' SQLite database."""
    local_state_path = os.path.join(dump_path, 'Local State')
    key = get_browser_key(local_state_path)
    if not key:
        return []

    db_path = os.path.join(dump_path, 'Login Data')
    if not os.path.isfile(db_path):
        print(f"Database file not found at {db_path}")
        return []

    shutil.copy2(db_path, 'Login Data.db')  # Copy database to avoid access issues
    conn = sqlite3.connect('Login Data.db')
    cursor = conn.cursor()
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')

    passwords = []
    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]
        decrypted_password = decrypt_password(encrypted_password, key)

        # Only add entries with non-empty username and password
        if username and decrypted_password:
            passwords.append({
                'url': url,
                'username': username,
                'password': decrypted_password
            })

    cursor.close()
    conn.close()
    os.remove('Login Data.db')  # Remove the temporary database file

    return passwords


def save_passwords_to_file(passwords, output_file):
    """Save the extracted passwords to a file."""
    with open(output_file, 'w', encoding='utf-8') as file:
        for entry in passwords:
            file.write(f"URL/Hostname: {entry.get('url', entry.get('hostname'))}\n")
            file.write(f"Username: {entry['username']}\n")
            file.write(f"Password: {entry['password']}\n")
            file.write("\n")

def main():
    base_path = input("Enter the path to the folder containing browser subfolders (e.g., E:\\dump): ")
    output_file = input("Enter the name of the output file: ")

    browsers = ['chrome', 'brave', 'edge', 'firefox']
    all_passwords = []

    for browser in browsers:
        dump_path = os.path.join(base_path, browser.capitalize())
        if os.path.exists(dump_path):
            if browser in ['chrome', 'brave', 'edge']:
                if os.path.exists(os.path.join(dump_path, 'Login Data')) and os.path.exists(os.path.join(dump_path, 'Local State')):
                    print(f"Processing {browser}...")
                    passwords = extract_chrome_passwords(dump_path)
                    all_passwords.extend(passwords)
                    print(f"Passwords extracted for {browser}")
                else:
                    print(f"Required files not found for {browser}.")
            elif browser == 'firefox':
                browser_backups_folder = os.path.join(base_path, "Firefox")
                savelocation = browser_backups_folder
                login_data_path = os.path.join(savelocation, "logins.json")
                local_state_path = os.path.join(savelocation, "key4.db")
                a = DecryptLogins(login_data_path, local_state_path, '')
                all_passwords.extend(a)
                output_file_path = output_file

                if os.path.exists(login_data_path) and os.path.exists(local_state_path):
                    print('Attempting to decrypt the logins.json/key4.db files...')
                    print(f"logins.json path: {login_data_path}")
                    print(f"key4.db path: {local_state_path}")
                    print('')

                else:
                    print(f"Folder for {browser} does not exist at the specified path.")

    # Save all extracted passwords
    save_passwords_to_file(all_passwords, output_file)
    print(f"All passwords saved in {output_file}")

if __name__ == "__main__":
    main()
