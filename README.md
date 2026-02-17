# Generador de llaves V2

## Miembros del grupo

| Nombre             | Código    | Correo electrónico           |
|--------------------|-----------|------------------------------|
| Adrian Velasquez   | 202222737 | a.velasquezs@uniandes.edu.co |
| Andres Botero Ruiz | 202223503 | a.boteror@uniandes.edu.co    |
| Sergio Castaño     | 202310390 | sa.castanoa1@uniandes.edu.co |

## Descripción del programa
En este repositorio encuentra el código del generador de llaves simétricas y asimétricas para encriptar y desencriptar archivos.

## Uso del código
Ejecutar el siguiente comando para generar llaves:

```zsh
python3 kgen.py <modo> <tamanio_llave> <nombre_archivo>
```

Donde 
`<modo>` es el modo de operación a utilizar (s o a, para simétrico o asimétrico respectivamente), 
`<tamanio_llave>` es el tamaño de la llave a generar (en bits) y 
`<nombre_archivo>` es el nombre del archivo (sin extensiones) donde se guardará la llave generada.

Los valores por defecto son:
- `<modo>`: s para simétrico
- `<tamanio_llave>`: 16 bytes (128 bits) para simétrico y 2048 bits para asimétrico
- `<nombre_archivo>`: k -> k.key para simétrico y k_private.pem/k_public.pem para asimétrico

## Ejemplo de uso

Asumiendo que se está corriendo desde `~/`, el comando para generar una llave simétrica de 16 bytes sería:

### Generar una llave simétrica de 16 bytes
```zsh
python3 kgen.py s 128 k
```
El resultado es un archivo binario de 16 bytes y se guardará en `~/k.key`.

### Generar un par de llaves asimétricas de 2048 bits
```zsh
python3 kgen.py a 2048 k
```
El resultado es un par de archivos PEM, `k_private.pem` y `k_public.pem`, que contienen la llave privada y pública respectivamente, y se guardarán en `~/`.