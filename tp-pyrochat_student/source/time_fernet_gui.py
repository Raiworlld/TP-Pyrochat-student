import time
import logging
import dearpygui.dearpygui as dpg
import hashlib
import hmac
import os
import base64

from cryptography.fernet import Fernet
from basic_gui import BasicGUI, DEFAULT_VALUES
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from chat_client import ChatClient
from generic_callback import GenericCallback
from Crypto.Cipher import AES
from cryptography.fernet import InvalidToken


# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "foo",
    "password" : ""
}


class TimeFernetGUI(FernetGUI):
    """
    GUI for a chat client that uses Fernet encryption with a time-based TTL.
    """

    TTL = 30  # Time-to-Live in seconds

    # cette fonction encrypt un message en utilisant la cle et le temps actuel comme timestamp
    def encrypt_at_time(data, key):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        timestamp = int(time.time())
        cipher = Fernet(key)
        token = cipher.encrypt(f"{data}{timestamp}".encode('utf-8'))
        return token.decode('utf-8')

    # cette fonction decrypt un message en utilisant la cle et le timestamp
    def decrypt_at_time(token, key):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        cipher = Fernet(key)
        try:
            plain = cipher.decrypt(token.encode('utf-8')).decode('utf-8')
            data, timestamp = plain[:-10], int(plain[-10:])
            if int(time.time()) - timestamp > TimeFernetGUI.TTL:
                raise InvalidToken("Token has expired.")
            return data
        except InvalidToken as e:
            logging.error(f"Failed to decrypt message: {e}")
            return None

    # cette fonction encrypt un message avec Fernet
    def encrypt(self, data, key):
        token = self.encrypt_at_time(data, key)
        return token

    # cette fonction decrypt un message avec Fernet
    def decrypt(self, token, key):
        data = self.decrypt_at_time(token, key)
        return data


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = TimeFernetGUI()
    client.create()
    client.loop()
