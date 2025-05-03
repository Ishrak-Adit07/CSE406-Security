import socket
import threading

clients = {}

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    name = conn.recv(1024).decode()
    clients[name] = conn
    welcome_msg = f"Server: Welcome {name}!"
    conn.send(welcome_msg.encode())

    while True:
        try:
            msg = conn.recv(1024).decode()
            if not msg:
                break

            if ":" not in msg:
                conn.send(b"Invalid format. Use recipient:message\n")
                continue

            recipient, message = msg.split(":", 1)
            recipient = recipient.strip()
            message = message.strip()

            if recipient in clients:
                full_msg = f"[{name}]: {message}".encode()
                clients[recipient].send(full_msg)
            else:
                conn.send(b"Recipient not found.\n")

        except:
            break

    print(f"[DISCONNECTED] {addr}")
    del clients[name]
    conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 5555))
    server.listen()

    print("[STARTED] Server is listening on port 5555")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
