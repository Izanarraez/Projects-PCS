# -*- coding: utf-8 -*-
"""
Created on Sun Sep 27 23:07:12 2026

@author: izana
"""
from string import ascii_uppercase as ALFA

ALFA = ALFA[:14] + "Ñ" + ALFA[14:]

N = len(ALFA)

cifrado = "NGTUQARW YN RLYI RINÑADN, ILBQG VL GMII T FVSDPSLOG TOACSFLNRNPW QIHQ LE DIIS GC ÑIPI, QIHQ LE JPSGY NR MIMHNY VRN OIAEUOUO; ODOG LTVSHW IW QC VL DSOUYT; TOYW RWÑRNEG LS SWQKDNLE VU FHLCA; QIHQ R NIMINNQ IAFMQWN ENAXYKBYTR TUMBJK RRSNLE XPG EEVWH. GPGLTFII ODFRS GWC EKU KICB GÑY XRN N LOL YO DA YIH, KPG VS QS BINKK: AXSW OUO DOG BSHKTAOG, LSLYEYOG I IW UERBNA Ñ UKOLUYPH; SGNA LCB HBKU TAILOEYU, RLXP AIÑ QMRCB BWXKRNCB Ñ FUU THUKEM; T NDESIRIÑ, UHN UÑKSGGL LCB GÑY XAVQU FIN UNS YICIÑ B DOG AWUKU. VSHM BÑIFH EG MA UUÑANC XOLU GD OHAE, KPG VS YWHSXC LIA XSMUT; EAG KKFLNV TQUSL VWVN HPCI LCKA NURSN GLTN QELICUA GPC WNTRR. DIHNDÑHS ODOGXQ FAOMBIÑ, CFDNTEM HKVNHAOM QKÑIYWI, R GNVGNTEM UN MIQTFI MWV FQUSUYÑHS; NBW KPG, TUNURI HQKIYWI, VYUTAABOFKU." 

def descifradoVigenere(mensaje, clave):
    texto_descifrado = ""
    indice_clave = 0
    
    for caracter in mensaje.upper():
        if caracter in ALFA:
            idx_cifrado = ALFA.index(caracter)
            idx_letra_clave = ALFA.index(clave[indice_clave % len(clave)])
            
            #Aplicamos el módulo 26 erróneo que usó el autor como lenguaje ingles
            idx_descifrado = (idx_cifrado - idx_letra_clave) % 26
            texto_descifrado += ALFA[idx_descifrado]
            
            indice_clave += 1
        else:
            texto_descifrado += caracter
            
    return texto_descifrado

b = descifradoVigenere(cifrado,"UCRANIOS")
print(b)