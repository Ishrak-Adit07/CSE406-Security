import socket
import threading
import time
import os
import ast
import hashlib

task1_file = '2005105_task1'
task1 = __import__(task1_file)
task2_file = '2005105_task2'
task2 = __import__(task2_file)

BLOCK_SIZE = 16

class AliceClient:
    def __init__(self, host='localhost', port=5555):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((host, port))
        self.client.send(b"alice") 
        
        time.sleep(1)
        self.iv = os.urandom(BLOCK_SIZE)

    def share_parameters(self):
        curve, G = task2.generate_parameters(128)
        self.curve = curve
        self.G = G
        self.p = curve.p
        self.a = curve.a
        self.b = curve.b

        self.private_key = task2.generate_private_key(curve)
        self.public_key = task2.generate_public_key(self.private_key, self.G, self.curve)
        self.other_public_key = None
        self.shared_key = None

        print("Self public Key: ", self.public_key)

        dh_message = f"bob:KEYS:{self.G}||{self.a}||{self.b}||{self.p}||{self.public_key}"
        self.client.send(dh_message.encode())
        print("Sent curve parameters and public key to Bob.")
        time.sleep(1)

    def receive_messages(self):
        while True:
            try:
                msg = self.client.recv(1024).decode()
                if msg:
                    if msg.split(":")[1].startswith(" KEYS"):
                        self.other_public_key = ast.literal_eval(msg.split(":")[2])
                        print(f"Received public key from Bob: {self.other_public_key}")
                        self.shared_key = task2.generate_shared_key(self.private_key, self.other_public_key, self.curve)
                        print(f"Shared secret key: {self.shared_key}")
                        print("Ready to chat securely.")

                        x_bytes = self.shared_key[0].to_bytes((self.shared_key[0].bit_length() + 7) // 8, 'big')
                        y_bytes = self.shared_key[1].to_bytes((self.shared_key[1].bit_length() + 7) // 8, 'big')
                        combined_bytes = x_bytes + y_bytes
                        hashed = hashlib.sha256(combined_bytes).digest()
                        aes_key = hashed[:16]
                        print(f"AES key: {aes_key}")

                        self.shared_key = task1.handle_key(aes_key.hex())
                        print(f"Shared handled key: {self.shared_key}")
                    elif msg.startswith("["):
                        ciphertext = msg.split(": ")[1]
                        ciphertext_bytes = ast.literal_eval(ciphertext)
                        padded_decrypted_text, decrypted_text, decryption_time = task1.aes_decrypt_cbc(ciphertext_bytes, self.shared_key)
                        print(f"Decryption time: {decryption_time}")
                        print(f"Decrypted message: {decrypted_text}")
                        print("Reply to bob: ")
                    else:
                        print("\n" + msg)
            except Exception as e:
                print(f"Error: {e}")
                break

    def send_messages(self):
        while True:
            msg = input()
            padded_plain_text, ciphertext, encryption_time, key_expansion_time = task1.aes_encrypt_cbc(msg, self.shared_key, self.iv)
            print("Encrypted text: ", ciphertext.hex())
            print(f"Encryption time: {encryption_time}")
            text_to_send = f"bob: {ciphertext}"
            self.client.send(text_to_send.encode())

    def run(self):
        recv_thread = threading.Thread(target=self.receive_messages)
        recv_thread.start()

        send_thread = threading.Thread(target=self.send_messages)
        send_thread.start()


if __name__ == "__main__":
    alice = AliceClient()
    alice.run()
    alice.share_parameters()
