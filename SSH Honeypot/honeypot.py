import paramiko
import threading
import socket

HOST_KEY = paramiko.RSAKey.generate(2048)
LOGFILE = 'ssh_honeypot3.log'

class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(f'[AUTH] Attempted login with username "{username}" and password "{password}"')
        with open(LOGFILE, 'a') as f:
            f.write(f'[AUTH] Attempted login with username "{username}" and password "{password}"\n')

        if username == 'admin' and password == 'password':
            print(f'[AUTH] Login successful for username "{username}" and password "{password}"')
            with open(LOGFILE, 'a') as f:
                f.write(f'[AUTH] Login successful for username "{username}" and password "{password}"\n')
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

def handle_client(client):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    server = SSHServer()
    try:
        transport.start_server(server=server)
        channel = transport.accept(1)
        if channel is not None:
            channel.close()
        transport.close()
    except paramiko.SSHException as e:
        print(f'[ERROR] SSHException: {e}')
        with open(LOGFILE, 'a') as f:
            f.write(f'[ERROR] SSHException: {e}\n')
        transport.close() 
    except EOFError as e:
        print(f'[ERROR] EOFError: {e}')
        with open(LOGFILE, 'a') as f:
            f.write(f'[ERROR] EOFError: {e}\n')
        transport.close()
    except Exception as e:
        print(f'[ERROR] Exception: {e}')
        with open(LOGFILE, 'a') as f:
            f.write(f'[ERROR] Exception: {e}\n')
            transport.close()

def main():
    ssh_port = 22
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', ssh_port))
    sock.listen(100)
    print(f'Started SSH honeypot on port {ssh_port}')
    with open(LOGFILE, 'a') as f:
        f.write(f'Started SSH honeypot on port {ssh_port}\n')
    while True:
        client, addr = sock.accept()
        print(f'[INFO] Received connection from {addr[0]}:{addr[1]}')
        with open(LOGFILE, 'a') as f:
            f.write(f'[INFO] Received connection from {addr[0]}:{addr[1]}\n')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()


if __name__ == '__main__':
    main()
