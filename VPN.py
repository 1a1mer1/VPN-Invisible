import logging
import os
import argparse
import socket
import threading
import ipaddress
import sys

logging.basicConfig(level=logging.DEBUG)

# VPN sınıfı
class VPN:
    def __init__(self, server_ip='192.168.1.100', openvpn_port=1194, ikev2_port=500, l2tp_port=1701, wireguard_port=51820):
        self.server_ip = server_ip
        self.openvpn_port = openvpn_port
        self.ikev2_port = ikev2_port
        self.l2tp_port = l2tp_port
        self.wireguard_port = wireguard_port
        self.openvpn_server_socket = None
        self.ikev2_server_socket = None
        self.l2tp_server_socket = None
        self.wireguard_server_socket = None
        self.openvpn_clients = []
        self.ikev2_clients = []
        self.l2tp_clients = []
        self.wireguard_clients = []

    def start(self):
        # Log kayıtlarının tutulmaması için aşağıdaki satırları ekleyin
        logging.getLogger().setLevel(logging.CRITICAL)
        os.environ['PYTHONWARNINGS'] = "ignore:Failed to import pyasn1.*"

        logging.info(f'Starting VPN server on {self.server_ip}...')
        self.openvpn_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.openvpn_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.openvpn_server_socket.bind((self.server_ip, self.openvpn_port))
        self.openvpn_server_socket.listen(5)
        openvpn_thread = threading.Thread(target=self.handle_openvpn_clients)
        openvpn_thread.start()

        self.ikev2_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ikev2_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.ikev2_server_socket.bind((self.server_ip, self.ikev2_port))
        self.ikev2_server_socket.listen(5)
        ikev2_thread = threading.Thread(target=self.handle_ikev2_clients)
        ikev2_thread.start()

        self.l2tp_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.l2tp_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.l2tp_server_socket.bind((self.server_ip, self.l2tp_port))
        self.l2tp_server_socket.listen(5)
        l2tp_thread = threading.Thread(target=self.handle_l2tp_clients)
        l2tp_thread.start()

        self.wireguard_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.wireguard_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.wireguard_server_socket.bind((self.server_ip, self.wireguard_port))
        wireguard_thread = threading.Thread(target=self.handle_wireguard_clients)
        wireguard_thread.start()

    def handle_openvpn_clients(self):
        while True:
            try:
                client_socket, client_address = self.openvpn_server_socket.accept()
                logging.info(f'New OpenVPN client connected from {client_address[0]}:{client_address[1]}')
                client_handler_thread = threading.Thread(target=self.handle_openvpn_client, args=(client_socket,))
                client_handler_thread.start()
                self.openvpn_clients.append(client_handler_thread)
            except:
                logging.exception('An error occurred while handling OpenVPN client')

    def handle_openvpn_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)
        except:
            logging.exception('An error occurred while handling OpenVPN client')
        finally:
            client_socket.close()
            logging.info('OpenVPN client disconnected')

    def handle_ikev2_clients(self):
        while True:
            try:
                client_socket, client_address = self.ikev2_server_socket.accept()
                logging.info(f'New IKEv2/IPsec client connected from {client_address[0]}:{client_address[1]}')
                client_handler_thread = threading.Thread(target=self.handle_ikev2_client, args=(client_socket,))
                client_handler_thread.start()
                self.ikev2_clients.append(client_handler_thread)
            except:
                logging.exception('An error occurred while handling IKEv2/IPsec client')

    def handle_ikev2_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)
        except:
            logging.exception('An error occurred while handling IKEv2/IPsec client')
        finally:
            client_socket.close()
            logging.info('IKEv2/IPsec client disconnected')

    def handle_l2tp_clients(self):
        while True:
            try:
                client_socket, client_address = self.l2tp_server_socket.accept()
                logging.info(f'New L2TP/IPsec client connected from {client_address[0]}:{client_address[1]}')
                client_handler_thread = threading.Thread(target=self.handle_l2tp_client, args=(client_socket,))
                client_handler_thread.start()
                self.l2tp_clients.append(client_handler_thread)
            except:
                logging.exception('An error occurred while handling L2TP/IPsec client')

    def handle_l2tp_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)
        except:
            logging.exception('An error occurred while handling L2TP/IPsec client')
        finally:
            client_socket.close()
            logging.info('L2TP/IPsec client disconnected')

    def handle_wireguard_clients(self):
        while True:
            try:
                data, address = self.wireguard_server_socket.recvfrom(1024)
                logging.info(f'New WireGuard client connected from {address[0]}:{address[1]}')
                self.wireguard_server_socket.sendto(data, address)
            except:
                logging.exception('An error occurred while handling WireGuard client')


def activate_virtualenv():
    venv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'venv')
    if sys.platform == 'win32':
        activate_path = os.path.join(venv_path, 'Scripts', 'activate.bat')
    else:
        activate_path = os.path.join(venv_path, 'bin', 'activate')
    if os.path.exists(activate_path):
        activate_cmd = f'source {activate_path}' if sys.platform != 'win32' else activate_path
        activate_cmd += f' && set PYTHONPATH={os.path.dirname(os.path.abspath(__file__))}'
        os.system(activate_cmd)
    else:
        print(f"Sanal ortam etkinleştirme komut dosyası bulunamadı: {activate_path}")




def run_app():
    # Sanal ortamı etkinleştir
    activate_virtualenv()

    # Komut satırı argümanlarını al
    parser = argparse.ArgumentParser(description='VPN Server')
    parser.add_argument('--openvpn-port', type=int, default=1194,
                        help='OpenVPN port number (default: 1194)')
    parser.add_argument('--ikev2-port', type=int, default=500,
                        help='IKEv2/IPsec port number (default: 500)')
    parser.add_argument('--l2tp-port', type=int, default=1701,
                        help='L2TP/IPsec port number (default: 1701)')
    parser.add_argument('--wireguard-port', type=int, default=51820,
                        help='WireGuard port number (default: 51820)')
    args = parser.parse_args()

    # VPN sınıfını başlat
    vpn_server = VPN(openvpn_port=args.openvpn_port,
                      ikev2_port=args.ikev2_port,
                      l2tp_port=args.l2tp_port,
                      wireguard_port=args.wireguard_port)
    vpn_server.start()

# Uygulama her çalıştığında run_app() işlevini çağır
if __name__ == '__main__':
    run_app()