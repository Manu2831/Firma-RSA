import random
from math import gcd

def egcd(a, b):  #Euclides muchachones
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No existe inverso")
    return x % m

def is_prime(n, k=15): #Saber si es primo
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    # descomponer n-1 = 2^s * d
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # iteraciones aleatorias
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def random_prime(bits=16):
    while True:
        p = random.getrandbits(bits) | 1 | (1 << (bits - 1))  # forzar impar y bit alto
        if is_prime(p):
            return p

# --- construcción de claves ------------------------------------------
def generate_keypair(bits=16):
    p = random_prime(bits)
    q = random_prime(bits)
    while q == p:
        q = random_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    # elegir e: suele usarse 65537; aquí buscamos uno pequeño coprimo
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (e, n), (d, n), p,q, phi # (public_key, private_key)

# --- hash simplificado -----------------------------------------------
def simple_hash(msg: str, n: int) -> int:
    """Suma de códigos ASCII mod n"""
    return sum(ord(c) for c in msg) % n

# --- firma y verificación --------------------------------------------
def sign(msg: str, priv_key):
    d, n = priv_key
    h = simple_hash(msg, n)
    return pow(h, d, n), h

def verify(msg: str, signature: int, pub_key):
    e, n = pub_key
    h_expected = simple_hash(msg, n)
    h_from_sig = pow(signature, e, n)
    return h_expected == h_from_sig
def datos_verify(msg: str, signature: int, pub_key):
    e, n = pub_key
    h_expected = simple_hash(msg, n)
    h_from_sig = pow(signature, e, n)
    return h_expected, h_from_sig

# ----------------- DEMO rápida --------------------------------------------------------------
if __name__ == "__main__":
    print("=== Simulador de Firma Digital (RSA + Hash) ===")


    print("\nEste es el proceso de cifrado para crear y verificar un mensaje mediante firma digital\n")
    print("----------------1. Generación de las claves pública y privada----------------")
     # Generar claves

    public_k, private_k,p_primo,q_primo, phi = generate_keypair(bits=12)
    e,n =public_k
    d,n=private_k

    mcd_ephi,_,_=egcd(e,phi)
    print(f"Se generan dos numeros primos diferentes:{p_primo} y {q_primo}.\n Se calculan n: p*q= {p_primo}* {q_primo}={n} y phi: (p - 1) * (q - 1)={p_primo-1}* {q_primo-1}={phi}. \n e es un entero tal que 1<e<phi, y sea coprimo con phi, osea mcd(e,phi)={mcd_ephi}={1}. El programa usa el e menor que cumpla: e es {e}. \n d es el inv. mult. de e mod phi, d es {modinv(e,phi)}={d}. e*d mod phi=1, {(e*d)%phi}")

    print("Claves generadas.")
    print("Clave pública (e, n):", public_k)
    print("Clave privada (d, n):", private_k)



    print("\n----------------2. Firmar un mensaje----------------")

    print(f"\n Se requiere el mensaje a enviar\n")
    mensaje = input("Ingresa el mensaje a firmar: ")
    firma, hash = sign(mensaje, private_k)
    print(f"\n Con el mensaje: '{mensaje}', se toma como string, y se cifra con un hash simple, El mensaje genera el siguiente hash: {hash}\n Se toma el hash y la clave privada {private_k}, y se eleva el hash al exponente privado d: {d} y se le saca modulo RSA n:{n}= {hash}^{d} mod {n}={firma}")

    print(f"El emisor envia el mensaje '{mensaje}' y la firma {firma} al receptor, que debera conocer la clave pública {public_k}")

    
    print("\n----------------3. Verificar una firma----------------")

    es_valida = verify(mensaje, firma, public_k)
    mensajehash, firmahash=datos_verify(mensaje, firma, public_k)
    print(f"\n El receptor requiere verificar si el mensaje ha sido modificado o enviado por el emisor\n Se tiene el mensaje '{mensaje}', la firma {firma} y  la clave pública {public_k}")

    print(f"Se toman el mensaje: '{mensaje}' y se cifra en hash. El mensaje genera el siguiente hash: {mensajehash}\n Se toma la firma: {firma}, y se eleva el hash al exponente publico e: {e} y se le saca modulo RSA n:{n}= {firma}^{e} mod {n}={firmahash}. Si el Hash del mensaje y el Hash de la firma son iguales, el mensaje es legítimo: {mensajehash}={firmahash}")

    print("¡Gracias por usar este software!")