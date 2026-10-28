import secrets
import hashlib
from bitarray import bitarray

def crear_clave_maestra():
    return secrets.token_bytes(20) #para resistir un ataque de numeros seudoaleatorios (calve de 20 bytes)

def expansion_clave(clave): #clave maestra (coge los 20 bytes y los estira hasta crear 1024 numeros enteros de 32 bits)

    num_gen = []

    cont = 0

    while(len(num_gen) < 1024):

        bytes_cont = cont.to_bytes(4, byteorder='big') #pasa cont a bytes (4 bytes)

        datos_entr = clave + bytes_cont
        bloque_aleatorio = hashlib.sha1(datos_entr).digest()

        bits = bitarray()
        bits.frombytes(bloque_aleatorio)

        for x in range(0,160,32):
            cortes = bits[x:x+32]
            
            transf = int.from_bytes(cortes.tobytes(), byteorder='big')

            num_gen.append(transf)

        cont += 1

    #Tablas de memoria precalculadas de sha-1
    T = num_gen[:512] #Trabla transformacion principal
    R = num_gen[512:768] #Tabla inicializacion
    S = num_gen[768:1024] #Tabla de salida

    return T,R,S

def desp_cir(x,n):
    #Como python no tiene limete de memoria matematica esto hace es recortal lo que pase de 32 bits (0xFFFFFFFF)
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF 


def initialize(n,l,R,T): 
    #Las tablas T,R,S tienen que generar un flujo de datos aleatorio con la misma longitud del mensaje

    A = n ^ R[4*l]
    B = desp_cir(n,8) ^ R[(4*l)+1]
    C = desp_cir(n,16) ^ R[(4*l)+2]
    D = desp_cir(n,24) ^ R[(4*l)+3]

    for _ in range(2):

        P = A & 0x7fc
        B = (B + T[P//4]) & 0xFFFFFFFF
        A = desp_cir(A,9)

        P = B & 0x7fc
        C = (C + T[P//4]) & 0xFFFFFFFF
        B = desp_cir(B,9)

        P = C & 0x7fc
        D = (D + T[P//4]) & 0xFFFFFFFF
        C = desp_cir(C,9)

        P = D & 0x7fc
        A = (A + T[P//4]) & 0xFFFFFFFF
        D = desp_cir(D,9)

    n1, n2, n3, n4 = D, B, A, C

    P = A & 0x7fc
    B = (B + T[P//4]) & 0xFFFFFFFF
    A = desp_cir(A,9)

    P = B & 0x7fc
    C = (C + T[P//4]) & 0xFFFFFFFF
    B = desp_cir(B,9)

    P = C & 0x7fc
    D = (D + T[P//4]) & 0xFFFFFFFF
    C = desp_cir(C,9)

    P = D & 0x7fc
    A = (A + T[P//4]) & 0xFFFFFFFF
    D = desp_cir(D,9)

    return A, B, C, D, n1, n2, n3, n4

def generar_claves(a,n,L):

    T,R,S = a

    y = b""
    l = 0

    while(len(y) < L):

        A, B, C, D, n1, n2, n3, n4 = initialize(n,l,R,T)

        for i in range(1,65):

            P = A & 0x7fc
            B = (B + T[P//4]) & 0xFFFFFFFF
            A = desp_cir(A,9)
            B = B ^ A

            Q = B & 0x7fc
            C = C ^ T[Q//4]
            B = desp_cir(B,9)
            C = (C + B) & 0xFFFFFFFF

            P = (P+C) & 0x7fc
            D = (D + T[P//4]) & 0xFFFFFFFF
            C = desp_cir(C,9)
            D = D ^ C

            Q = (Q+D) & 0x7fc
            A = A ^ T[Q//4]
            D = desp_cir(D,9)
            A = (A + D) & 0xFFFFFFFF

            P = (P+A) & 0x7fc
            B = B ^ T[P//4]
            A = desp_cir(A,9)

            Q = (Q+B) & 0x7fc
            C = (B + T[Q//4]) & 0xFFFFFFFF
            B = desp_cir(B,9)
        
            P = (P+C) & 0x7fc
            D = D ^ T[P//4]
            C = desp_cir(C,9)

            Q = (Q+D) & 0x7fc
            A = (A + T[Q//4]) & 0xFFFFFFFF
            D = desp_cir(D,9)

            sal1 = (B + S[4*i-4]) & 0xFFFFFFFF
            sal2 = (C ^ S[4*i-3]) & 0xFFFFFFFF
            sal3 = (D + S[4*i-2]) & 0xFFFFFFFF
            sal4 = (A ^ S[4*i-1]) & 0xFFFFFFFF

            bits_salida = bitarray()

            bits_salida.frombytes(sal1.to_bytes(4, byteorder='big'))
            bits_salida.frombytes(sal2.to_bytes(4, byteorder='big'))
            bits_salida.frombytes(sal3.to_bytes(4, byteorder='big'))
            bits_salida.frombytes(sal4.to_bytes(4, byteorder='big'))

            y += bits_salida.tobytes()

            if len(y) >= L:
                return y[:L]

            if i % 2 != 0:
                A = (A + n1) & 0xFFFFFFFF
                B = (B + n2) & 0xFFFFFFFF
                C = (C ^ n1) & 0xFFFFFFFF
                D = (D ^ n2) & 0xFFFFFFFF
            else:
                A = (A + n3) & 0xFFFFFFFF
                B = (B + n4) & 0xFFFFFFFF
                C = (C ^ n3) & 0xFFFFFFFF
                D = (D ^ n4) & 0xFFFFFFFF

        l += 1

    return y[:L]

def cifrado_descrifrado(datos,claves):

    cifrado = bitarray()

    for i in range(len(datos)):
        byte_dato = datos[i]
        byte_flujo = claves[i]

        xor = byte_dato ^ byte_flujo

        cifrado.append(xor)

    return bytes(cifrado)

def main():
    # 1. Preparar el mensaje que quieres cifrar
    texto_plano = "Hola, este es un mensaje secreto procesado con SEAL!"
    mensaje_bytes = texto_plano.encode('utf-8') 
    
    # 2. Inicialización del sistema SEAL
    print("1. Fabricando clave maestra secreta...")
    clave = crear_clave_maestra()
    
    print("2. Expandiendo clave (Generando tablas T, R, S)...")
    a = expansion_clave(clave)

    # 3. Preparar los parámetros de entrada y generar el flujo
    n = 0                         
    L_bytes = len(mensaje_bytes)  

    print("3. Generando el flujo de claves (Keystream)...")
    flujo_de_claves = generar_claves(a, n, L_bytes)

    # ---------------------------------------------------------
    # 4. El Cifrado Real usando la nueva función
    # ---------------------------------------------------------
    mensaje_cifrado = cifrado_descrifrado(mensaje_bytes, flujo_de_claves)
    
    print("\n4. Mensaje CIFRADO (datos incomprensibles):")
    print(f"   {mensaje_cifrado}")

    # ---------------------------------------------------------
    # 5. Descifrar (Volver a usar la misma función)
    # ---------------------------------------------------------
    # Le pasamos el texto ilegible y el mismo flujo, y el XOR lo revierte
    mensaje_descifrado_bytes = cifrado_descrifrado(mensaje_cifrado, flujo_de_claves)
    
    print("\n5. Mensaje DESCIFRADO:")
    print(f"   {mensaje_descifrado_bytes.decode('utf-8')}")

if __name__ == "__main__":
    main()


            






