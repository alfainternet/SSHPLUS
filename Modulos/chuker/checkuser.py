import os
import sqlite3
import argparse
import subprocess
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import cgi
import io
import json

def user_usuario(username):
    with open('/etc/passwd', 'r') as f:
        for line in f:
            if username in line:
                return True
    return False

def user_conectados(username):
    ps_output = os.popen(f'ps -u {username} | grep sshd | wc -l').read()
    return ps_output.strip()

def user_limite(username):
    users_db_path = '/root/usuarios.db'

    if os.path.isfile(users_db_path):
        with open(users_db_path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2 and parts[0] == username:
                    return parts[1]
                
    else:
        connection = sqlite3.connect('/etc/DTunnelManager/db.sqlite3')
        cursor = connection.cursor()
        cursor.execute("SELECT connection_limit FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return str(result[0]).zfill(3)
        return "000"



def get_chage_co_date(username):
    try:
        chage_output = subprocess.check_output(["chage", "-l", username]).decode("utf-8")
        co_date_str = next((line.split(":")[-1].strip() for line in chage_output.splitlines() if "Account expires" in line), None)
        return datetime.strptime(co_date_str, "%b %d, %Y") if co_date_str else None
    except subprocess.CalledProcessError:
        return None

def user_data(username):
    co_date = get_chage_co_date(username)
    return co_date.strftime("%d/%m/%Y") if co_date else "N/A"

def user_dias_restantes(username):
    co_date = get_chage_co_date(username)
    return str((co_date - datetime.now()).days) if co_date else "N/A"

def format_date_for_anymod(date_string):
    date = datetime.strptime(date_string, "%d/%m/%Y")
    formatted_date = date.strftime("%Y-%m-%d-")
    return formatted_date

class CustomHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            result = json.loads(post_data.decode('utf-8'))
        except Exception as e:
            result = post_data.decode('utf-8')
        print(result)

        global username, client_ip
        try:
            if self.path.startswith('/checkUser'):
                username = result['user']
                if username is None:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'Bad Request')
                    return

                user_info = {
                    "username": username,
                    "count_connection": user_conectados(username),
                    "expiration_date": user_data(username),
                    "expiration_days": user_dias_restantes(username),
                    "limiter_user": user_limite(username)
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user_info).encode())
            elif self.path.startswith('/anymod'):

                post_data_file = io.BytesIO(result.encode('utf-8'))

                form = cgi.FieldStorage(
                    fp=post_data_file, 
                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': 'application/x-www-form-urlencoded'}
                )

                username = form.getvalue('username')
                deviceid = form.getvalue('deviceid')
                if username and deviceid is None:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b'Bad Request')
                    return

                if int(user_conectados(username)) >= 1:
                    is_active = "true"
                else: 
                    is_active = "false"

                user_info = {
                  "USER_ID": username,
                  "DEVICE": deviceid,
                  "is_active": is_active,
                  "expiration_date": format_date_for_anymod(user_data(username)),
                  "expiry": f"{user_dias_restantes(username)} dias.",
                  "uuid": "null"
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user_info).encode())
                
            else: 
                self.send_response(404)
                self.end_headers()
                self.wfile.write("Url invalida, verifique e tente novamente !".encode('utf-8'))

        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_GET(self):
        if self.path.startswith('/gl/check/'):
            start_index = self.path.find('/check/') + len('/check/')
            end_index = self.path.find('?')

            if end_index != -1:
                username = self.path[start_index:end_index]
            else:
                username = self.path[start_index:]

            client_ip = self.client_address[0]
            try:
                user_info = {
                    "username": username,
                    "count_connection": user_conectados(username),
                    "expiration_date": user_data(username),
                    "expiration_days": user_dias_restantes(username),
                    "limit_connection": user_limite(username)
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user_info).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        elif self.path.startswith('/dtmod/check/'):
            username = self.path.split('/')[3]
            client_ip = self.client_address[0]
            try:
                user_info = {
                    "username": username,
                    "count_connections": int(user_conectados(username)),
                    "expiration_date": user_data(username),
                    "expiration_days": int(user_dias_restantes(username)),
                    "limit_connections": int(user_limite(username)),
                    "status": 200
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user_info).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())
        elif self.path.startswith('/atx?user='):
            start_index = self.path.find('/atx?user=') + len('/atx?user=')

            username = self.path[start_index:]

            client_ip = self.client_address[0]
            try:
                user_info = {
                    "username": username,
                    "cont_conexao": user_conectados(username),
                    "data_expiracao": user_data(username),
                    "dias_expiracao": user_dias_restantes(username),
                    "limite_user": user_limite(username)
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(user_info).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(str(e).encode())

            


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Servidor HTTP com porta personalizável")
    parser.add_argument('--port', type=int, default=5555, help="Porta do servidor (padrão: 5555)")
    args = parser.parse_args()

    porta = args.port
    server = HTTPServer(('0.0.0.0', porta), CustomHandler)
    print(f"Servidor iniciado na porta {porta}")
    server.serve_forever()
