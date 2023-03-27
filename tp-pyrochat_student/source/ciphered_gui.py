import logging
import dearpygui.dearpygui as dpg
import hashlib
import hmac
import os

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

class CipheredGUI (BasicGUI): #Creation de la classe CipheredGUI
    """
    GUI for a chat client. 
    """
    def __init__(self, key=None)->None: #La variable key est initialise a none
        # constructor
        super().__init__() #pour appeler la méthode init() de la classe parent (BasicGUI) 
        self._client = None
        self._callback = None
        self._key = key   # Champ pour la definition d`une cle
        self._log = logging.getLogger(self.__class__.__name__)


    def _create_chat_window(self)->None:
        # chat windows
        # known bug : the add_input_text do not display message in a user friendly way
        with dpg.window(label="Chat", pos=(0, 0), width=800, height=600, show=False, tag="chat_windows", on_close=self.on_close):
            dpg.add_input_text(default_value="Readonly\n\n\n\n\n\n\n\nfff", multiline=True, readonly=True, tag="screen", width=790, height=525)
            dpg.add_input_text(default_value="some text", tag="input", on_enter=True, callback=self.text_callback, width=790)

    # Dans cette fonction un champ pour le password ete cree
    def _create_connection_window(self)->None:
        # windows about connexion
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            
            for field in ["host", "port", "name", "password"]: # Password ajoute un mot de passe
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    if field == "password": # Ajoute un champ de saisie de mot de passe
                      dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}", password=True)
                    else:
                      dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")
                      
                dpg.add_button(label="Connect", callback=self.run_chat)

    def _create_menu(self)->None:
        # menu (file->connect)
        with dpg.viewport_menu_bar():
            with dpg.menu(label="File"):
                dpg.add_menu_item(label="Connect", callback=self.connect)

    def create(self):
        # create the context and all windows
        dpg.create_context()

        self._create_chat_window()
        self._create_connection_window()
        self._create_menu()        
            
        dpg.create_viewport(title='Secure chat', width=800, height=600)
        dpg.setup_dearpygui()
        dpg.show_viewport()

    def update_text_screen(self, new_text:str)->None:
        # from a nex_text, add a line to the dedicated screen text widget
        text_screen = dpg.get_value("screen")
        text_screen = text_screen + "\n" + new_text
        dpg.set_value("screen", text_screen)

    def text_callback(self, sender, app_data)->None:
        # every time a enter is pressed, the message is gattered from the input line
        text = dpg.get_value("input")
        self.update_text_screen(f"Me: {text}")
        self.send(text)
        dpg.set_value("input", "")

    def connect(self, sender, app_data)->None:
        # callback used by the menu to display connection windows
        dpg.show_item("connection_windows")
        
    def _derive_key(self, password:str)->bytes:
        # Derive key from password using PBKDF2HMAC with SHA256
        salt = b'IwantChocolateToday' # a salt
        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=16, # 16 bytes key
            salt=salt,
            iterations=100000, # number of iterations, increase for stronger security (but slower)
        )
        return kdf.derive(password.encode())

    def run_chat(self, sender, app_data)->None:
        # callback used by the connection windows to start a chat session
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port} with password {password}")


        # derive key from password using PBKDF2HMAC
        self._key = self._derive_key(password)

        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    # Cette fonction encrypt un message
    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = AES.new(self._key, AES.MODE_CBC,iv)
        padding_lenght = AES.block_size - (len(plaintext) % AES.block_size)
        padded_plaintext = plaintext + padding_lenght * chr(padding_length)
        ciphertext = cipher.encrypt(padded_plaintext.encode('utf-8'))
        return (iv, ciphertext)
    
    # Cette fonction decrypt un message
    def decrypt(self, ciphertext):
        iv, encrypted = chipertext
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode('utf-8').strip()

    def on_close(self):
        # called when the chat windows is closed
        self._client.stop()
        self._client = None
        self._callback = None

    def recv(self)->None:
        # function called to get incoming messages and display them
        if self._callback is not None:
            for user, message in self._callback.get():
                decrypted_message = self.decrypt(message)
                self.update_text_screen(f"{user} : {decrypted_message}")
            self._callback.clear()

    def send(self, text)->None:
        # function called to send a message to all (broadcasting)
        iv, encrypted_text = self.encrypt(text)
        self._client.send_message((iv, encrypted_text))

    def loop(self):
        # main loop
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()

        dpg.destroy_context()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = CipheredGUI()
    client.create()
    client.loop()