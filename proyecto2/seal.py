import secrets
import hashlib
from bitarray import bitarray

def crear_clave_maestra():
    return secrets.token_bytes(20) #para resistir un ataque de numeros seudoaleatorios

def expansion_clave(clave): #clave maestra

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
    T = num_gen[:512]
    R = num_gen[512:768]
    S = num_gen[768:1024]

    return T,R,S

def desp_cir(x,n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def initialize(n,l,R,T):

    A = n ^ R[4*l]
    B = desp_cir(n,8) ^ R[(4*l)+1]
    C = desp_cir(n,16) ^ R[(4*l)+2]
    D = desp_cir(n,24) ^ R[(4*l)+3]

    for _ in range(2):

        P = A & 0x7fc
        B = B + T[P/4]
        A = desp_cir(A,9)

        P = B & 0x7fc
        C = C + T[P/4]
        B = desp_cir(B,9)

        P = C & 0x7fc
        D = D + T[P/4]
        C = desp_cir(C,9)

        P = D & 0x7fc
        A = A + T[P/4]
        D = desp_cir(D,9)

    n1, n2, n3, n4 = D, B, A, C

    P = A & 0x7fc
    B = B + T[P/4]
    A = desp_cir(A,9)

    P = B & 0x7fc
    C = C + T[P/4]
    B = desp_cir(B,9)

    P = C & 0x7fc
    D = D + T[P/4]
    C = desp_cir(C,9)

    P = D & 0x7fc
    A = A + T[P/4]
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
            B = B + T[P/4]
            A = desp_cir(A,9)
            B = B ^ A

            Q = B & 0x7fc
            C = C ^ T[Q/4]
            B = desp_cir(B,9)
            C = C + B

            P = (P+C) & 0x7fc
            D = D + T[P/4]
            C = desp_cir(C,9)
            D = D ^ C

            Q = (Q+D) & 0x7fc
            A = A ^ T[Q/4]
            D = desp_cir(D,9)
            A = A + D

            P = (P+A) & 0x7fc
            B = B ^ T[P/4]
            A = desp_cir(A,9)

            Q = (Q+B) & 0x7fc
            C = B + T[Q/4]
            B = desp_cir(B,9)
        
            P = (P+C) & 0x7fc
            D = D ^ T[P/4]
            C = desp_cir(C,9)

            Q = (Q+D) & 0x7fc
            A = A + T[Q/4]
            D = desp_cir(D,9)

            sal1 = (B + S[4*i-4]) & 0xFFFFFFFF
            sal2 = (C ^ S[4*i-3]) & 0xFFFFFFFF
            sal3 = (D + S[4*i-2]) & 0xFFFFFFFF
            sal4 = (A ^ S[4*i-1]) & 0xFFFFFFFF

            






