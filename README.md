# redes-tp2-NAT-2C2026

### Ejecución del controlador

Desde una terminal, ejecutar:  
`python3 pox/pox.py log.level --DEBUG protorouter`

### Ejecución de la topología

En otra terminal, ejecutar:  
`sudo python3 topo.py`

### Orden de ejecución recomendado

- Iniciar el controlador POX.
- Ejecutar la topología en Mininet.
- Verificar que el switch se conecte al controlador.

### Verificación básica

- Iniciar la red.
- Desde la CLI de Mininet:
    - Probar conectividad: `h2 ping h1`