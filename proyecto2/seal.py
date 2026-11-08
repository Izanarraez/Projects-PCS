import secrets
import hashlib
from bitarray import bitarray

def crear_clave_maestra():
    return secrets.token_bytes(20)

def obtener_palabra(clave,i):
    cont = i // 5
    resto = i % 5 

    bytes_cont = cont.to_bytes(4, byteorder='big') #pasa cont a bytes (4 bytes)

    datos_entr = clave + bytes_cont
    bloque_aleatorio = hashlib.sha1(datos_entr).digest()

    bits = bitarray()
    bits.frombytes(bloque_aleatorio)

    cortes = bits[resto*32:(resto+1)*32]

    return int.from_bytes(cortes.tobytes(), byteorder='big')

def expansion_clave(clave): #clave maestra (coge los 20 bytes)

    #Tablas de memoria precalculadas de sha-1
    T = [obtener_palabra(clave,i) for i in range(512)] # 0 a 512
    S = [obtener_palabra(clave, 0x1000 + i) for i in range(256)] #(0x1000 es 4096) 
    R = [obtener_palabra(clave, 0x2000 + i) for i in range(256)] #(0x2000 es 8192)
    
    return T,R,S

def desp_cir(x,n):
    #Como python no tiene limete de memoria matematica esto hace es recortar lo que pase de 32 bits (0xFFFFFFFF)
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF 


def initialize(n,l,R,T): 

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
            C = (C + T[Q//4]) & 0xFFFFFFFF
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

        cifrado.frombytes(xor.to_bytes(1, byteorder='big'))

    return cifrado.tobytes()

def main():

    salida = True

    while(salida):
        print("1.Enviar mensaje (cifrar)")
        print("2.Recibir mensaje (descifrar)")
        print("3.Mostrar variables")
        print("4.Salir")

        decision = int(input("Elige una opcion:"))

        match(decision):
            case 1:
                mensaje = input("Introduce un texto:")
                n = int(input("Introduce posicion de cifrado (n):"))
                
                print("1.Fabricando clave.........")
                clave = crear_clave_maestra()

                print("2.Expandiendo clave........")
                a = expansion_clave(clave)

                mensaje_bytes = mensaje.encode('utf-8')
                L = len(mensaje_bytes)

                print("3.Generar flujo de claves..")
                claves = generar_claves(a,n,L)

                print("4.Cifrado..................\n")
                mensaje_cifrado = cifrado_descrifrado(mensaje_bytes,claves)


            case 2:

                try:
                    mensaje_cifrado
                except NameError:
                    print("Primero hay que enviar el mensaje\n")
                    continue

                print("1.Clave maestra recibida.................")
                print("2.Indice n recibido.................")
                print("3.Expandiendo clave........")
                a = expansion_clave(clave)
    
                L = len(mensaje_cifrado)
                
                print("4.Generar flujo de claves..")
                claves = generar_claves(a,n,L)

                mensaje_descifrado = cifrado_descrifrado(mensaje_cifrado,claves)

                print(f"Mensaje descifrado:{mensaje_descifrado.decode('utf-8')}\n")

            case 3:

                try:
                    mensaje_cifrado
                except NameError:
                    print("Primero hay que enviar el mensaje\n")
                    continue
                
                print(f"\nClave maestra: {clave.hex()}")
                print(f"Flujo de claves: {claves.hex()}")
                print(f"Indice n: {"0x{:08X}".format(n)}")
                print(f"Mensaje cifrado: {mensaje_cifrado.hex()}")
                print(f"Mensaje descifrado:{mensaje_descifrado.hex()}\n")

            case 4:
                salida = False

if __name__ == "__main__":
    main()
