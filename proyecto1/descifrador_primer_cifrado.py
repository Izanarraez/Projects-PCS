# -*- coding: utf-8 -*-
"""
Created on Fri Sep 18 20:01:35 2026

@author: izana
"""
import math

texto_cifrado = "Tirlnesv adhlsNrlooO r  hnaMwho.ire nimR tlidst nohewhn vgrketrselti  o ntkodr nohew numOgn,ibh,na htdre srgtes ynhf isonMMmdeh naotdre sOgl n d nre  rbeh drS eshn t, e-ir neoeei eL rnh drS n eaet Ogimatkimeooehle e-uh f ln oe rndef ohkeeooehlet l otn n nhnn  fr ai f kneSoDo hf,ft  ,oDri   fr ai otlR hetgadeedIL  tdeRoEid erwrta  oadt radstIL  tdeR h,ife o l  s naMwho."

def descifrar_tranposicion(cifrado,num_columnas):

    longitud = len(cifrado)
    num_filas = math.ceil(longitud / num_columnas)
        
    celdas_vacias = (num_columnas * num_filas) - longitud
        
    longitud_columnas = [num_filas] * num_columnas
        
    for i in range(num_columnas - celdas_vacias, num_columnas):
        longitud_columnas[i] -= 1
            
    columnas = []
    indice = 0
    for col in range(num_columnas):
        columnas.append(cifrado[indice : indice + longitud_columnas[col]])
        indice += longitud_columnas[col]
            
    texto = []
    for fila in range(num_filas):
        for col in range(num_columnas):
            if fila < len(columnas[col]):
                texto.append(columnas[col][fila])
                    
    resultado = "".join(texto)
        
        
    print("\n")
    print(resultado)

descifrar_tranposicion(texto_cifrado,7)