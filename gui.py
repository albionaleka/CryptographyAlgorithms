import customtkinter as ctk
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib

class Program(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cryptography Methods")
        self.geometry("800x600")
        self.columnconfigure(1, weight=100)
        self.columnconfigure(2, weight=100)
        self.columnconfigure(3, weight=100)
        self.columnconfigure(4, weight=100)

        self.frame = ctk.CTkScrollableFrame(self, width=800, height=600)
        self.frame.grid(row=0, column=1, columnspan=4, rowspan=7, sticky="nsew")

        self.title = ctk.CTkLabel(self.frame, text="Cryptographic Methods 🖥️", font=('Verdana', 30))
        self.title.grid(row=1, column=0, pady=30, columnspan=4)

        self.message = ctk.CTkEntry(self.frame, placeholder_text="Message to be encrypted", font=('Verdana', 16), width=450, height=30)
        self.message.grid(row=2, column=0, columnspan=2, pady=10, padx=10)

        self.shift = ctk.CTkEntry(self.frame, placeholder_text="Shift", font=('Verdana', 16), height=30)
        self.shift.grid(row=2, column=2, columnspan=1, pady=10, padx=10)

        self.button = ctk.CTkButton(self.frame, text="Display", font=('Verdana', 16), command=self.display, height=30)
        self.button.grid(row=2, column=3, columnspan=1, pady=10)

        self.caesarLabel = ctk.CTkLabel(self.frame, text="Caesar Cipher:", font=('Verdana', 16))
        self.caesarLabel.grid(row=3, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.caesarResult = ctk.CTkTextbox(self.frame, width=550, height=50)
        self.caesarResult.grid(row=3, column=1, pady=10, padx=10, columnspan=3)

        self.caesarCrackLabel = ctk.CTkLabel(self.frame, text="Crack Caesar Cipher:", font=('Verdana', 16))
        self.caesarCrackLabel.grid(row=4, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.caesarCrackResult = ctk.CTkTextbox(self.frame, width=550, height=150)
        self.caesarCrackResult.grid(row=4, column=1, pady=10, padx=10, columnspan=3)

        self.reverseLabel = ctk.CTkLabel(self.frame, text="Reverse Cipher:", font=('Verdana', 16))
        self.reverseLabel.grid(row=5, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.reverseResult = ctk.CTkTextbox(self.frame, width=550, height=50)
        self.reverseResult.grid(row=5, column=1, pady=10, padx=10, columnspan=3)

        self.fernetLabel = ctk.CTkLabel(self.frame, text="Using Fernet:", font=('Verdana', 16))
        self.fernetLabel.grid(row=6, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.fernetResult = ctk.CTkTextbox(self.frame, width=550, height=50)
        self.fernetResult.grid(row=6, column=1, pady=10, padx=10, columnspan=3)

        self.sendLabel = ctk.CTkLabel(self.frame, text="Send:", font=('Verdana', 16))
        self.sendLabel.grid(row=7, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.sendResult = ctk.CTkTextbox(self.frame, width=550, height=75)
        self.sendResult.grid(row=7, column=1, pady=10, padx=10, columnspan=3)

        self.receiveLabel = ctk.CTkLabel(self.frame, text="Receive:", font=('Verdana', 16))
        self.receiveLabel.grid(row=8, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.receiveResult = ctk.CTkTextbox(self.frame, width=550, height=75)
        self.receiveResult.grid(row=8, column=1, pady=10, padx=10, columnspan=3)

        self.rsaLabel = ctk.CTkLabel(self.frame, text="RSA:", font=('Verdana', 16))
        self.rsaLabel.grid(row=9, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.rsaResult = ctk.CTkTextbox(self.frame, width=550, height=175)
        self.rsaResult.grid(row=9, column=1, pady=10, padx=10, columnspan=3)

        self.hashLabel = ctk.CTkLabel(self.frame, text="Password Hash:", font=('Verdana', 16))
        self.hashLabel.grid(row=10, column=0, pady=10, padx=10, columnspan=1, sticky="w")

        self.hashResult = ctk.CTkTextbox(self.frame, width=550, height=50)
        self.hashResult.grid(row=10, column=1, pady=10, padx=10, columnspan=3)


    def display(self):
        message = self.message.get()
        shiftEntry = self.shift.get()

        if shiftEntry:
            shift = int(shiftEntry)
        else:
            shift = 3

        self.caesar(message, shift)
        self.reverse(message)
        self.fernet(message.encode())
        self.send(message.encode())
        self.receive()
        self.rsa(message.encode())
        self.hash(message)

        caesar = self.caesarResult.get("1.0", "end").strip()
        self.crackCaesar(caesar)


    def caesar(self, m, s):
        self.caesarResult.delete(0.0, 'end')

        encrypted = ""

        for i in range(len(m)):
            char = m[i]

            if char.isupper():
                encrypted += chr((ord(char) + s - 65) % 26 + 65)
            elif char.islower():
                encrypted += chr((ord(char) + s - 97) % 26 + 97)
            else:
                encrypted += char

        self.caesarResult.insert(ctk.END, encrypted)

    def crackCaesar(self, message):
        self.caesarCrackResult.delete(0.0, 'end')

        results = []

        for s in range(1, 26):
            decrypted = ""
            for i in range(len(message)):
                char = message[i]

                if char.isupper():
                    decrypted += chr((ord(char) - s - 65) % 26 + 65)
                elif char.islower():
                    decrypted += chr((ord(char) - s - 97) % 26 + 97)
                else:
                    decrypted += char
                
            results.append(decrypted)

        for i, word in enumerate(results):
            self.caesarCrackResult.insert(ctk.END, f"Key {i + 1}:  {word}\n")
    
    def reverse(self, message):
        self.reverseResult.delete(0.0, 'end')

        encrypted = ''
        for i in range(len(message) - 1, -1, -1):
            encrypted += message[i]
        
        self.reverseResult.insert(ctk.END, encrypted)

    def fernet(self, message):
        self.fernetResult.delete(0.0, 'end')

        key = Fernet.generate_key()
        cipher = Fernet(key)

        encrypted = cipher.encrypt(message)

        self.fernetResult.insert(ctk.END, encrypted.decode())

    
    def send(self, message):
        self.sendResult.delete(0.0, 'end')

        key = Fernet.generate_key()
        cipher = Fernet(key)

        encrypted = cipher.encrypt(message)
        
        self.sendResult.insert(ctk.END, f"Encrypted message: {encrypted.decode()} \nKey: {key}")

        with open("key", "wb") as key_file:
            key_file.write(key)

        with open("message", "w") as message_file:
            message_file.write(encrypted.decode())

    def receive(self):
        self.receiveResult.delete(0.0, 'end')

        key = open("key", "rb").read()
        cipher = Fernet(key)

        with open("message", "r") as message_file:
            encrypted = message_file.read().encode()

        decrypted = cipher.decrypt(encrypted)

        self.receiveResult.insert(ctk.END, f"Before decryption: {encrypted.decode()} \nDecrypted message: {decrypted.decode()}")

    def rsa(self, message):
        self.rsaResult.delete(0.0, 'end')

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        encrypted = public_key.encrypt(
            message,
            cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    algorithm=cryptography.hazmat.primitives.hashes.SHA256()
                ),
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                label=None
            )
        )

        decrypted = private_key.decrypt(
            encrypted,
            cryptography.hazmat.primitives.asymmetric.padding.OAEP(
                mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                    algorithm=cryptography.hazmat.primitives.hashes.SHA256()
                ),
                algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
                label=None
            )
        ).decode()

        self.rsaResult.insert(ctk.END, f"Encrypted message: {encrypted.hex()} \nDecrypted message: {decrypted}")


    def hash(self, password):
        self.hashResult.delete(0.0, 'end')

        hash = hashlib.sha256(password.encode()).hexdigest()
        self.hashResult.insert(ctk.END, hash)

app = Program()
app.mainloop()