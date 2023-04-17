import paramiko
import threading
import socket
from flask import Flask, render_template, request, redirect, url_for
import queue
from flask_cors import CORS

HOST_KEY = paramiko.RSAKey.generate(2048)
LOGFILE = 'ssh_honeypot.log'

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
log_queue = queue.Queue()

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
        log_queue.put((f'[ERROR] SSHException: {e}\n', 'error'))
        transport.close() 
    except EOFError as e:
        log_queue.put((f'[ERROR] EOFError: {e}\n', 'error'))
        transport.close()
    except Exception as e:
        log_queue.put((f'[ERROR] Exception: {e}\n', 'error'))
        transport.close()
    else:
        log_queue.put((f'[INFO] Connection closed\n', 'info'))
        
app = Flask(__name__, template_folder='template')
CORS(app)
    
@app.route('/index', methods=['GET'])
def index():
    with open(LOGFILE, 'r') as f:
        log_data = f.read()
        
        print("\n")
        
    return render_template('index.html', log_data=log_data)

# create a global flag to indicate whether the honeypot is running
honeypot_running = False
# create a global flag to indicate whether the honeypot is running
honeypot_running = False

from flask import redirect, url_for

@app.route('/start', methods=['GET', 'POST'])
def start():
    global honeypot_running
    if request.method == 'POST':
        if not honeypot_running:
            # start the honeypot
            ssh_port = request.form['port']
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', int(ssh_port)))
            sock.listen(100)
            print(f'Started SSH honeypot on port {ssh_port}')
            with open(LOGFILE, 'a') as f:
                f.write(f'Started SSH honeypot on port {ssh_port}\n')
            honeypot_running = True
            while honeypot_running:
                client, addr = sock.accept()
                print(f'[INFO] Received connection from {addr[0]}:{addr[1]}')
                with open(LOGFILE, 'a') as f:
                    f.write(f'[INFO] Received connection from {addr[0]}:{addr[1]}\n')
                client_handler = threading.Thread(target=handle_client, args=(client,))
                client_handler.start()
            # redirect to the stop page
            return redirect(url_for('stop'))
        else:
            # honeypot is already running
            print('Honeypot is already running')
            with open(LOGFILE, 'a') as f:
                f.write('Honeypot is already running\n')
        return render_template('start.html', honeypot_running=honeypot_running)

    # render the start page
    return render_template('start.html', honeypot_running=honeypot_running)

@app.route('/stop', methods=['POST'])
def stop():
    global honeypot_running
    honeypot_running = False
    print('Honeypot stopped')
    with open(LOGFILE, 'a') as f:
        f.write('Honeypot stopped\n')
    return render_template('start.html', honeypot_running=honeypot_running)


if __name__ == '__main__':
    honeypot_thread = threading.Thread(target=index)
    honeypot_thread.start()
    app.debug = True 
    app.run(host="0.0.0.0", port=80)




