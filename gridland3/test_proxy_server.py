import socket
import threading

LOG_FILE = "proxy_logs.txt"

def handle_client(client_socket):
    request = client_socket.recv(4096)
    if not request:
        client_socket.close()
        return

    # Log the request
    with open(LOG_FILE, "a") as f:
        f.write(request.decode('utf-8', errors='ignore').split('\n')[0] + "\n")

    # Simple response to close the connection, as we are just logging
    client_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")
    client_socket.close()

def run_proxy():
    # Clear log file
    with open(LOG_FILE, "w") as f:
        f.write("")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 8888))
    server.listen(5)
    print("Proxy server listening on port 8888...")

    while True:
        client_sock, addr = server.accept()
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_sock,)
        )
        client_handler.start()

if __name__ == '__main__':
    run_proxy()
