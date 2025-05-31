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
    return (e, n), (d, n)   # (public_key, private_key)

# --- hash simplificado -----------------------------------------------
def simple_hash(msg: str, n: int) -> int:
    """Suma de códigos ASCII mod n"""
    return sum(ord(c) for c in msg) % n

# --- firma y verificación --------------------------------------------
def sign(msg: str, priv_key):
    d, n = priv_key
    h = simple_hash(msg, n)
    return pow(h, d, n)

def verify(msg: str, signature: int, pub_key):
    e, n = pub_key
    h_expected = simple_hash(msg, n)
    h_from_sig = pow(signature, e, n)
    return h_expected == h_from_sig

# ----------------- DEMO rápida ---------------------------------------
if __name__ == "__main__":
    print("=== Simulador de Firma Digital (RSA + Hash) ===")

    # Generar claves
    public_k, private_k = generate_keypair(bits=12)
    print("Claves generadas.")
    print("Clave pública (e, n):", public_k)
    print("Clave privada (d, n):", private_k)

    while True:
        print("\n¿Qué deseas hacer?")
        print("1. Firmar un mensaje")
        print("2. Verificar una firma")
        print("3. Salir")

        opcion = input("Elige una opción: ")

        if opcion == "1":
            mensaje = input("Ingresa el mensaje a firmar: ")
            firma = sign(mensaje, private_k)
            print("Firma generada:", firma)

        elif opcion == "2":
            mensaje = input("Ingresa el mensaje a verificar: ")
            try:
                firma = int(input("Ingresa la firma recibida: "))
                es_valida = verify(mensaje, firma, public_k)
                if es_valida:
                    print("✅ Firma VÁLIDA. El mensaje es auténtico.")
                else:
                    print("❌ Firma NO válida. El mensaje fue alterado o la firma es falsa.")
            except ValueError:
                print("La firma debe ser un número entero.")

        elif opcion == "3":
            print("¡Hasta luego!")
            break
        else:
            print("Opción no válida. Intenta de nuevo.")