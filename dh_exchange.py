from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from common import deser_public_key, ser_public_key, recv, send, key_size

class DH_exchange:  
    def __init__(self, socket, role):
        """
        socket: The socket for communication.
        role: either "sender" or "reciever".
        """
        self.socket = socket
        self.role = role
        self.private_key = None
        self.public_key = None
        self.shared_key = None

    def generate_parameters(self):
        """Generate DH parameters (used by sender)."""
        return dh.generate_parameters(generator=2, key_size=key_size)

    def generate_keys(self, dh_params=None):
        """        
        dh_params: DH parameters (required for receiver).
        """
        if dh_params is None:
            dh_params = self.generate_parameters()
        self.private_key = dh_params.generate_private_key()
        self.public_key = self.private_key.public_key()
        return dh_params if self.role == "sender" else None

    def perform_key_exchange(self):
        """DH key exchange based on the role."""
        try:
            if self.role == "sender":

                dh_params = self.generate_keys()
                send(self.socket, dh_params.parameter_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.ParameterFormat.PKCS3
                ))
                send(self.socket, ser_public_key(self.public_key))
                peer_pub_key = deser_public_key(recv(self.socket))
                self.shared_key = self.private_key.exchange(peer_pub_key)
                print(f"secussfully got a shared key-> {self.shared_key}")

            elif self.role == "reciever":

                dh_params = serialization.load_pem_parameters(recv(self.socket))
                self.generate_keys(dh_params)
                send(self.socket, ser_public_key(self.public_key))

                peer_pub_key = deser_public_key(recv(self.socket))
                shared_key = self.private_key.exchange(peer_pub_key)
                print(f"secussfully got a shared key-> {shared_key}")

            else:
                raise ValueError("Invalid role. Must be 'sender' or 'receiver'.")

            self.shared_key = self.private_key.exchange(peer_pub_key)
            print(f"successfully generated shared key: {self.shared_key}")
            return self.shared_key

        except Exception as e:
            print(f"Error during key exchange: {e}")
            raise