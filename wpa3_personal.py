# Mario Montanuy and Chaymaa Dkouk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from Crypto.Hash import SHA256
import pyshark
import hmac
import hashlib

a = int("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16)
h = int("1", 16)
curve = ECC._curves["P-256"]
p = int(hex(curve.p), 16)
b = int(hex(curve.b), 16)
n = int(hex(curve.order), 16)

"""
Validates that the expected and the result are the same on their first and last characters.
"""


def validate_result_start_end(start_chars, end_chars, result):
    print("Expected: " + start_chars + "..." + end_chars)
    print("Result:   " + result)
    if (
        start_chars == result[: len(start_chars)]
        and end_chars == result[-len(end_chars) :]
    ):
        print("\nCorrect\n")
    else:
        print("\nIncorrect\n")


"""
Validates that the expected and the result are completely equals.
"""


def validate_result_equals(expected, result):
    print("Expected: " + expected)
    print("Result:   " + result)
    if expected == result:
        print("\nCorrect\n")
    else:
        print("\nIncorrect\n")


"""
Creates an elliptic curve point from hexadecimal x and y values.
"""


def create_point(x_value, y_value):
    x = int(x_value, 16)
    y = int(y_value, 16)
    curve_name = "P-256"
    return ECC.EccPoint(x, y, curve=curve_name)


# Question 1

"""
Proves that given Px and Py are on the secp256r1 curve by checking the curve equation.
"""


def prove_secp256r1_point(Px, Py):
    py_result = (Py * Py) % p
    px_result = (Px * Px * Px + a * Px + b) % p

    if py_result == px_result:
        print(
            "The points Px and Py satisfy the curve equation. So P is a point of secp256r1\n"
        )
    else:
        print(
            "The points Px and Py do not satisfy the curve equation. So P is not a point of secp256r1\n"
        )


"""
Loads a private key from a PEM file.
"""


def get_private_key():
    pem_file_path = "data/example_private_key.pem"
    with open(pem_file_path, "rb") as pem_file:
        pem_data = pem_file.read()
    return serialization.load_pem_private_key(
        pem_data, password=None, backend=default_backend()
    )


"""
Validates and proves a point on the secp256r1 curve.
"""


def question1():
    private_key = get_private_key()
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_hex = public_der.hex()
    validate_result_start_end("3059", "85ee", public_hex)

    public_numbers = public_key.public_numbers()
    x = public_numbers.x
    y = public_numbers.y
    prove_secp256r1_point(int(x), int(y))
    return public_key, public_der


# Question 2

"""
Creates and proves a specific elliptic curve point.
"""


def question2():
    Px = "f6879bd7a8f49ad6a0cf49474bbd0abf710423cb46c8a0fe172edf33c60e1c6a"
    Py = "a791a8f81d203c746fd26d4d06ca9edb89fab7ff4be3032ba694c3ebde7f1f6c"
    P = create_point(Px, Py)
    validate_result_start_end("f687", "1c6a", Px)
    validate_result_start_end("a791", "1f6c", Py)
    prove_secp256r1_point(int(Px, 16), int(Py, 16))
    return P


# Question 3

"""
Extracts s, NP.x, and NP.y from a specific packet index in a PCAP file.
"""


def get_sx_NPx_NPy(index):
    capture = pyshark.FileCapture(
        "data/saepk.pcapng",
        display_filter="wlan.fixed.auth.alg==3",
        use_json=True,
        include_raw=True,
    )
    packet = capture[index].get_raw_packet()[58:154]
    s = packet[:32].hex()
    NPx = packet[32:64].hex()
    NPy = packet[64:96].hex()
    capture.close()
    return s, NPx, NPy


"""
Validates and proves the elliptic curve point from PCAP data.
"""


def question3():
    s1, NP1x, NP1y = get_sx_NPx_NPy(0)
    if 1 < int(s1, 16) < n:
        print("s1 is in the range of 1 and n")
    prove_secp256r1_point(int(NP1x, 16), int(NP1y, 16))
    NP1 = create_point(NP1x, NP1y)
    return s1, NP1


# Question 4

"""
Computes a point on the curve using given r2, s1, P, and NP1.
"""


def question4(P, s1, NP1):
    r2 = "782883c54a91fd380a7b5d06408ce37ac21164fec268b5ad59c504d9344e6a6c"
    K = int(r2, 16) * (int(s1, 16) * P + NP1)
    k_hex = hex(K.x)[2:]
    prove_secp256r1_point(int(K.x), int(K.y))
    validate_result_start_end("a65c", "27f9", k_hex)
    return K.x


"""
Generates keyseed and pmkid bytes from k and s1.
"""


def get_keyseed_pmkid_bytes(k, s1):
    s2, _, _ = get_sx_NPx_NPy(1)
    key = bytes([0x00] * 32)
    k_hex = hex(k)[2:]
    keyseed = hmac.new(key, bytes.fromhex(k_hex), hashlib.sha256).digest()
    pmkid_int = (int(s1, 16) + int(s2, 16)) % n
    pmkid_bytes = pmkid_int.to_bytes(32)
    return keyseed, pmkid_bytes


"""
Derives KCK from keyseed and pmkid bytes.
"""


def get_KCK(keyseed, pmkid_bytes):
    data_kck = b"\x01" + b"\x00" + b"SAE-PK keys" + pmkid_bytes + b"\x00\x03"
    return hmac.new(keyseed, data_kck, hashlib.sha256).digest()


"""
Derives PMK from keyseed and pmkid bytes.
"""


def get_PMK(keyseed, pmkid_bytes):
    data_pmk = b"\x02" + b"\x00" + b"SAE-PK keys" + pmkid_bytes + b"\x00\x03"
    return hmac.new(keyseed, data_pmk, hashlib.sha256).digest()


"""
Derives KEK from keyseed and pmkid bytes.
"""


def get_KEK(keyseed, pmkid_bytes):
    data_kek = b"\x03" + b"\x00" + b"SAE-PK keys" + pmkid_bytes + b"\x00\x03"
    return hmac.new(keyseed, data_kek, hashlib.sha256).digest()


"""
Handles the derivation of KCK, PMK, and KEK from k and s1.
"""


def get_KCK_PMK_KEK(k, s1):
    keyseed, pmkid_bytes = get_keyseed_pmkid_bytes(k, s1)
    kck = get_KCK(keyseed, pmkid_bytes)
    pmk = get_PMK(keyseed, pmkid_bytes)
    kek = get_KEK(keyseed, pmkid_bytes)
    validate_result_start_end("7a83", "214a", kck.hex())
    validate_result_start_end("f0ca", "032f", pmk.hex())
    validate_result_start_end("9e74", "e5c2", kek.hex())
    return kck, pmk, kek


# Question 5

"""
Computes and validates confirm1.
"""


def question5(kck):
    s1, NP1x, NP1y = get_sx_NPx_NPy(0)
    s2, NP2x, NP2y = get_sx_NPx_NPy(1)
    NP1 = bytes.fromhex(NP1x) + bytes.fromhex(NP1y)
    NP2 = bytes.fromhex(NP2x) + bytes.fromhex(NP2y)
    data = b"\x01\x00" + bytes.fromhex(s1) + NP1 + bytes.fromhex(s2) + NP2
    confirm1 = hmac.new(kck, data, hashlib.sha256).digest()
    validate_result_start_end("ac8f", "f59b", confirm1.hex())


# Question 6

"""
Extracts the encryption modifier from confirm2 packet in a PCAP file.
"""


def get_enc_modifier():
    capture = pyshark.FileCapture(
        "data/saepk.pcapng",
        display_filter="wlan.fixed.auth.alg==3",
        use_json=True,
        include_raw=True,
    )
    enc_mod = capture[3].get_raw_packet()[233:]
    capture.close()
    return enc_mod


"""
Computes and validates the modifier from the encryption modifier.
"""


def get_modifier(kek, enc_modifier):
    cipher = AES.new(kek, AES.MODE_SIV)
    try:
        return cipher.decrypt_and_verify(enc_modifier[16:], enc_modifier[:16])
    except ValueError as e:
        print(e)
        return b""


"""
Validates and proves the modifier.
"""


def question6(kek):
    enc_modifier = get_enc_modifier()
    validate_result_start_end("619a", "aec6", enc_modifier.hex())
    modifier = get_modifier(kek, enc_modifier)
    validate_result_start_end("e2c2", "17b5", modifier.hex())
    return modifier


# Question 7

"""
Creates a public key variation from the given public key.
"""


def get_pubkey2(public_key):
    return (
        public_key[0:1]
        + bytes([0x39])
        + public_key[2:24]
        + bytes([0x22])
        + public_key[25:26]
        + bytes([0x02])
        + public_key[27:59]
    )


"""
Extracts MAC addresses from the PCAP file.
"""


def get_MACs():
    capture = pyshark.FileCapture(
        "data/saepk.pcapng",
        display_filter="wlan.fixed.auth.alg==3",
        use_json=True,
        include_raw=True,
    )
    MAC_STA = capture[0].get_raw_packet()[36:42]
    MAC_AP = capture[0].get_raw_packet()[42:48]
    capture.close()
    return MAC_STA, MAC_AP


"""
Creates the dataTBS from the given pubkey2 and modifier.
"""


def get_dataTBS(pubkey2, modifier):
    s1, NP1x, NP1y = get_sx_NPx_NPy(0)
    s2, NP2x, NP2y = get_sx_NPx_NPy(1)
    NP1 = bytes.fromhex(NP1x) + bytes.fromhex(NP1y)
    NP2 = bytes.fromhex(NP2x) + bytes.fromhex(NP2y)
    MAC_STA, MAC_AP = get_MACs()
    return (
        NP2
        + NP1
        + bytes.fromhex(s2)
        + bytes.fromhex(s1)
        + modifier
        + pubkey2
        + MAC_AP
        + MAC_STA
    )


"""
Validates and proves the dataTBS.
"""


def question7(public_key, modifier):
    pubkey2 = get_pubkey2(public_key)
    dataTBS = get_dataTBS(pubkey2, modifier)
    validate_result_start_end("7199", "8223", dataTBS.hex())
    return dataTBS


# Question 8: Part 1

# # TODO BORRAR
# def get_sigAP():
#     capture = pyshark.FileCapture(
#         "data/saepk.pcapng",
#         display_filter="wlan.fixed.auth.alg==3",
#         use_json=True,
#         include_raw=True,
#     )
#     sigAP = capture[3].get_raw_packet()[98:169]
#     capture.close()
#     return sigAP

"""
Generates a signature from the given dataTBS.
"""


def generate_signature(dataTBS):
    private_key = get_private_key()
    dataTBS_hash = SHA256.new(dataTBS).digest()
    signature = private_key.sign(dataTBS_hash, ec.ECDSA(hashes.SHA256()))
    return signature


"""
Validates and proves the signature.
"""


def verify_signature(public_key, dataTBS, signature):
    hased_data = SHA256.new(dataTBS).digest()
    try:
        public_key.verify(signature, hased_data, ec.ECDSA(hashes.SHA256()))
        print("\nSignature is valid")
    except InvalidSignature:
        print("\nSignature is invalid")


"""
Generates and verifies a signature.
"""


def question8(public_key, dataTBS):
    sigAP = generate_signature(dataTBS)
    verify_signature(public_key, dataTBS, sigAP)


# Question 8: Part 2

"""
Extracts the HMAC part from the confirm2 in the PCAP file.
"""


def get_hmac_part_confirm2():
    capture = pyshark.FileCapture(
        "data/saepk.pcapng",
        display_filter="wlan.fixed.auth.alg==3",
        use_json=True,
        include_raw=True,
    )
    hmac = capture[3].get_raw_packet()[58:90]
    capture.close()
    return hmac


"""
Computes and validates the HMAC part from confirm2.
"""


def question8_2(kck):
    s1, NP1x, NP1y = get_sx_NPx_NPy(0)
    s2, NP2x, NP2y = get_sx_NPx_NPy(1)
    NP1 = bytes.fromhex(NP1x) + bytes.fromhex(NP1y)
    NP2 = bytes.fromhex(NP2x) + bytes.fromhex(NP2y)
    data = b"\x01\x00" + bytes.fromhex(s2) + NP2 + bytes.fromhex(s1) + NP1
    hmac_value = hmac.new(kck, data, SHA256).digest()
    hmac_part_confirm2 = get_hmac_part_confirm2()
    validate_result_equals(hmac_part_confirm2.hex(), hmac_value.hex())


"""
Main function to run all questions in sequence.
"""


def main():
    print("\n ------ Question 1 ------ \n")
    public_key, public_key_bytes = question1()
    print("\n ------ Question 2 ------ \n")
    P = question2()
    print("\n ------ Question 3 ------ \n")
    s1, NP1 = question3()
    print("\n ------ Question 4 ------ \n")
    k = question4(P, s1, NP1)
    print("\n ------ KCK PMK KEK ------ \n")
    kck, pmk, kek = get_KCK_PMK_KEK(k, s1)
    print("\n ------ Question 5 ------ \n")
    question5(kck)
    print("\n ------ Question 6 ------ \n")
    modifier = question6(kek)
    print("\n ------ Question 7 ------ \n")
    dataTBS = question7(public_key_bytes, modifier)
    print("\n ------ Question 8: Part 1 ------ \n")
    question8(public_key, dataTBS)
    print("\n ------ Question 8: Part 2 ------ \n")
    question8_2(kck)
    print("\n ------ End ------ \n")


if __name__ == "__main__":
    main()
