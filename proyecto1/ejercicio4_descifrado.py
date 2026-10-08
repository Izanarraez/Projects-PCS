# -*- coding: utf-8 -*-
"""
Created on Fri Oct  2 19:46:47 2026

@author: izana
"""

from string import ascii_uppercase as ALFA

ALFA = ALFA[:14] + "Ñ" + ALFA[14:]
N = len(ALFA)

cifrado = '...rlos lk haoavn htorhazoyj bz tvj ,zvkhyvs zvnoñ zvr ,yhisá lk zhkva ,zlrlahjzvs zhcb zhr ,zhtoyhkths zhpthyht zhr thazbn lC .fvk lr vathbj lsvT ...rhlko vlrlihjzhj ébx éz vt tl ,líy lz lbx ljlyhw lbx lynlrh vrrojlavya tb tvj ís h ltloc f ,"?vylahrH¿" :latlsljrbk vshrr vC ...zhkrhbn f zlazlrlj ,zhzvy zhrrojlyvrm zhr ,zhtlwh zhrvktágvy ,vjojvñ bz tvj latlshoioa hojoyhjh f ,vkhyw rh hc lz f ,varlbz vplk vC .vynlt rhazoyj lk zvphihyhjzl zvk rhbj zvybk tvz zvpv zbz lk lñjhihgh lk zvplwzl zvr vróK .zvzlbñ hclrr vt lbx ,tókvnrh lk vkva híyok lz lbx ,hylbm yvw vkthri tha ;lchbz ,vkbrlw ,vulbxlw zl vylahrH'

def descifrar_cesar(mensaje, clave):
    texto_descifrado = ""
    
    for caracter in mensaje:
       
        letra_mayus = caracter.upper()
        
        if letra_mayus in ALFA:
            
            if caracter.isupper():
                idx = (ALFA.index(letra_mayus) + (clave+2)) % N
                texto_descifrado += ALFA[idx]
                
            else:
                idx = (ALFA.index(letra_mayus) - clave) % N
                texto_descifrado += ALFA[idx].lower()
                
        else:
            texto_descifrado += caracter
            
    return texto_descifrado


print(descifrar_cesar(cifrado, 7)[::-1])