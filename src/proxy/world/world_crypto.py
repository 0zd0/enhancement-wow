import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SESSION_SEED = bytes.fromhex(
    "e81e8b5927621eaa861518eac0bf668c"
    "6dbf8393bcaa80525b1edc23a012b750"
)
CONTINUED_SEED = bytes.fromhex(
    "565c619c483a521f615d0549b29a39bf"
    "4b97b01bf96cded6801dab2602a99b9d"
)
ENCRYPTION_SEED = bytes.fromhex(
    "71c9ed5aa70e4dff4c36a65a3e468a4a"
    "5da148c830474adef60d6cbe6fe45573"
)


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha512")


def derive_session(key_data: bytes, server: bytes, client: bytes) -> bytes:
    if (len(key_data), len(server), len(client)) != (64, 32, 32):
        raise ValueError("Expected keyData[64] and two challenges[32]")

    seed = mac(sha512(key_data), server + client + SESSION_SEED)

    # Первые 40 байт SessionKeyGenerator<SHA512>.
    return sha512(
        sha512(seed[:32]) + bytes(64) + sha512(seed[32:])
    )[:40]


def derive_encryption(session: bytes, server: bytes, client: bytes) -> bytes:
    return mac(session, client + server + ENCRYPTION_SEED)[:32]


def decrypt(
        key: bytes,
        client: bool,
        counter: int,
        tag: bytes,
        data: bytes,
) -> bytes:
    iv = counter.to_bytes(8, "little") + (b"CLNT" if client else b"SRVR")
    decoder = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag, min_tag_length=12),
    ).decryptor()

    try:
        return decoder.update(data) + decoder.finalize()
    except InvalidTag as error:
        raise ValueError(
            f"AES-GCM tag failed: client={client}, counter={counter}; "
            "check secrets, build and capture completeness"
        ) from error

def encrypt(
    key: bytes,
    client: bool,
    counter: int,
    data: bytes,
) -> tuple[bytes, bytes]:
    iv = counter.to_bytes(8, "little") + (b"CLNT" if client else b"SRVR")
    encoder = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encoder.update(data) + encoder.finalize()
    return encoder.tag[:12], ciphertext