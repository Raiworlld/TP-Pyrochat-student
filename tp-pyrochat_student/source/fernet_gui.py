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

# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "foo",
    "password" : ""
}

class FernetGUI (CipheredGUI): #Creation de la classe CipheredGUI
    """
    GUI for a chat client Fernet encryption
    """
    def __init__(self, key=None)->None: 
        # constructor
        super().__init__() 
        self._client = None
        self._callback = None
        self._key = key
        self._log = logging.getLogger(self.__class__.__name__)


    def run_chat(self, sender, app_data)->None:
        # callback used by the connection windows to start a chat session
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port} with password {password}")


        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        self._key = hashlib.sha256()
        self._key.update(password.encode("utf-8"))
        self._key = base64.b64encode(self._key.digest())

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    # Cette fonction encrypt un message en utisant Fernet
    def encrypt(self, data, key):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        self.cipher = Fernet(key)
        return self.cipher.encrypt(data.encode('utf-8')).decode('utf-8')
    
    # Cette fonction decrypt un message en utisant Fernet
    def decrypt(self, data, key):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
        self.cipher = Fernet(key)
        return self.cipher.decrypt(data.encode('utf-8')).decode('utf-8')


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = FernetGUI()
    client.create()
    client.loop()