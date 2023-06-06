from typing import Tuple, Optional
import hashlib


p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

Point = Tuple[int, int]

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def is_infinite(P: Optional[Point]) -> bool:
    return P is None

def x(P: Point) -> int:
    assert not is_infinite(P)
    return P[0]

def y(P: Point) -> int:
    assert not is_infinite(P)
    return P[1]

def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return (x3, (lam * (x(P1) - x3) - y(P1)) % p)

def point_mul(P: Optional[Point], n: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (n >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

def bytes_from_int(x: int) -> bytes:
    return x.to_bytes(32, "big")

def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

def xor_bytes(b0: bytes, b1: bytes) -> bytes:
    return bytes(x ^ y for (x, y) in zip(b0, b1))

def lift_x(x: int) -> Optional[Point]:
    if x >= p:
        return None
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if pow(y, 2, p) != y_sq:
        return None
    return (x, y if y & 1 == 0 else p-y)

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")

def hash_sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def has_even_y(P: Point) -> bool:
    assert not is_infinite(P)
    return y(P) % 2 == 0

def pubkey_gen(seckey: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    P = point_mul(G, d0)
    assert P is not None
    return bytes_from_point(P)

def schnorr_sign(msg: bytes, seckey: bytes, aux_rand: bytes) -> bytes:
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    if len(aux_rand) != 32:
        raise ValueError('aux_rand must be 32 bytes instead of %i.' % len(aux_rand))
    P = point_mul(G, d0)
    assert P is not None
    d = d0 if has_even_y(P) else n - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    k0 = int_from_bytes(tagged_hash("BIP0340/nonce", t + bytes_from_point(P) + msg)) % n
    if k0 == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = point_mul(G, k0)
    assert R is not None
    k = n - k0 if not has_even_y(R) else k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge", bytes_from_point(R) + bytes_from_point(P) + msg)) % n
    sig = bytes_from_point(R) + bytes_from_int((k + e * d) % n)
    #debug_print_vars()
    if not schnorr_verify(msg, bytes_from_point(P), sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_verify(msg: bytes, pubkey: bytes, sig: bytes) -> bool:
    if len(pubkey) != 32:
        raise ValueError('The public key must be a 32-byte array.')
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')
    P = lift_x(int_from_bytes(pubkey))
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (P is None) or (r >= p) or (s >= n):
        #debug_print_vars()
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
    R = point_add(point_mul(G, s), point_mul(P, n - e))
    if (R is None) or (not has_even_y(R)) or (x(R) != r):
        #debug_print_vars()
        return False
    #debug_print_vars()
    return True

#seckey1_hex = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
#pubkey_hex="DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
#aux_rand_hex="0000000000000000000000000000000000000000000000000000000000000001"
#msg_hex="243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
#sig_hex="0E12B8C520948A776753A96F21ABD7FDC2D7D0C0DDC90851BE17B04E75EF86A47EF0DA46C4DC4D0D1BCB8668C2CE16C54C7C23A6716EDE303AF86774917CF928"

# testvector index 0
seckey_hex_0 = "0000000000000000000000000000000000000000000000000000000000000003"
pubkey_hex_0 ="F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
aux_rand_hex_0 ="0000000000000000000000000000000000000000000000000000000000000000"
msg_hex_0 ="0000000000000000000000000000000000000000000000000000000000000000"
sig_hex_0 ="E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"

# testvector index 1
seckey_hex_1 = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
pubkey_hex_1 ="DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
aux_rand_hex_1 ="0000000000000000000000000000000000000000000000000000000000000001"
msg_hex_1 ="243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
sig_hex_1 ="6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"

# testvector index 2
seckey_hex_2 = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
pubkey_hex_2 ="DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"
aux_rand_hex_2 ="C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906"
msg_hex_2 ="7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C"
sig_hex_2 ="5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"

# 0
msg_0 = bytes.fromhex(msg_hex_0)
sig_0 = bytes.fromhex(sig_hex_0)
seckey_0 = bytes.fromhex(seckey_hex_0)
pubkey_0 = bytes.fromhex(pubkey_hex_0)
aux_rand_0 = bytes.fromhex(aux_rand_hex_0)

sig_actual_0 = schnorr_sign(msg_0, seckey_0, aux_rand_0)

if sig_0 == sig_actual_0:
    print(' * Passed signing test.')
else:
    print(' * Failed signing test.')
    print('   Expected signature:', sig_0.hex().upper())
    print('   Actual signature:', sig_actual_0.hex().upper())

# 1
msg_1 = bytes.fromhex(msg_hex_1)
sig_1 = bytes.fromhex(sig_hex_1)
seckey_1 = bytes.fromhex(seckey_hex_1)
pubkey_1 = bytes.fromhex(pubkey_hex_1)
aux_rand_1 = bytes.fromhex(aux_rand_hex_1)

sig_actual_1 = schnorr_sign(msg_1, seckey_1, aux_rand_1)

if sig_1 == sig_actual_1:
    print(' * Passed signing test.')
else:
    print(' * Failed signing test.')
    print('   Expected signature:', sig_1.hex().upper())
    print('   Actual signature:', sig_actual_1.hex().upper())

# 2
msg_2 = bytes.fromhex(msg_hex_2)
sig_2 = bytes.fromhex(sig_hex_2)
seckey_2 = bytes.fromhex(seckey_hex_2)
pubkey_2 = bytes.fromhex(pubkey_hex_2)
aux_rand_2 = bytes.fromhex(aux_rand_hex_2)

sig_actual_2 = schnorr_sign(msg_2, seckey_2, aux_rand_2)

if sig_2 == sig_actual_2:
    print(' * Passed signing test.')
else:
    print(' * Failed signing test.')
    print('   Expected signature:', sig_2.hex().upper())
    print('   Actual signature:', sig_actual_2.hex().upper())
