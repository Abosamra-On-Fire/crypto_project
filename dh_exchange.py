from cryptography.hazmat.primitives.asymmetric import dh
from common import deser_public_key, ser_public_key, recv, send,key_size, serialization

def DH_exchange(s, type):
    if type == "sender":
        try:
            dh_params = dh.generate_parameters(generator=2, key_size=key_size)
            send(s, dh_params.parameter_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.ParameterFormat.PKCS3
                ))
            s_priv_key = dh_params.generate_private_key()
            s_pub_key = s_priv_key.public_key() 
            send(s, ser_public_key(s_pub_key))

            r_pub_key = deser_public_key(recv(s))
            shared_key = s_priv_key.exchange(r_pub_key)
            print(f"secussfully got a shared key-> {shared_key}")

            return shared_key
        except Exception as e:
            print(f"Error: {e}") 

    elif type == "reciever":
        try:
            dh_params = serialization.load_pem_parameters(recv(s))
            r_priv_key = dh_params.generate_private_key()
            r_pub_key = r_priv_key.public_key()
            send(s, ser_public_key(r_pub_key))

            s_pub_key = deser_public_key(recv(s))
            shared_key = r_priv_key.exchange(s_pub_key)
            print(f"secussfully got a shared key-> {shared_key}")

            return shared_key
        except Exception as e:
            print(f"Error: {e}")    