# TP2: SDN — NAT saliente con PAT (POX + Mininet)

Implementación de un **NAT saliente con traducción por puertos (PAT)** como
aplicación SDN: la lógica de traducción y el mantenimiento de estado corren en
un controlador **POX** (`ext/protorouter.py`), que instala reglas **OpenFlow**
en un switch de **Mininet** (`topo.py`) para que el forwarding posterior se
haga íntegramente en el plano de datos.

## Topología

```
                             port 1                    port 2
     ┌───────┐  IP: 200.0.0.254   /\  IP: 192.168.1.254      ┌───────┐
     │  h1   ├───────────────────/ s1 \────────────────────────│  h2   │
     └───────┘                   \    /                       └───────┘
  200.0.0.1/24                    \  /                    192.168.1.2/24
  DG: 200.0.0.254                  \/(port 3)             DG: 192.168.1.254
                                         ┌───────┐
                                         │  h3   │
                                         └───────┘
                                     192.168.1.3/24
                                     DG: 192.168.1.254
```

- **h1**: host en la red pública (servidor).
- **h2, h3**: hosts en la red privada (clientes). Ambos comparten la única IP
  pública del NAT (200.0.0.254) y pueden mantener conexiones simultáneas.
- **s1**: switch OpenFlow controlado por POX; el controlador lo hace actuar
  como router L3 con dos interfaces:

  | Interfaz  | IP            | MAC                 |
  |-----------|---------------|---------------------|
  | Pública   | 200.0.0.254   | `00:00:00:aa:aa:aa` |
  | Privada   | 192.168.1.254 | `00:00:00:bb:bb:bb` |

No hay entradas ARP estáticas en ningún host: toda la resolución de MACs se
hace con el protocolo ARP, manejado por el controlador.

## Ejecución

### Requisitos

- Python 3
- Mininet (entorno Linux — usar VM, WSL2 o máquina Linux)
- POX (incluido en este repositorio)

### Ejecución del controlador
Desde una terminal, ejecutar:
`python3 pox.py log.level --DEBUG protorouter`

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
    - Probar conectividad: `h2 ping -c 3 h1` y `h3 ping -c 3 h1`

### Pruebas de NAT con múltiples conexiones (TCP/UDP)

Abrir terminales por host:

```bash
mininet> xterm h1 h2 h3
```

Servidor TCP en `h1` (puerto 9000):

```bash
iperf -s -p 9000
```

Cliente en `h2`:

```bash
iperf -c 200.0.0.1 -p 9000 -t 5
```

Cliente en `h3` **al mismo tiempo** (conexión simultánea hacia el mismo
servidor, con distinto puerto origen → distinto puerto público del NAT):

```bash
iperf -c 200.0.0.1 -p 9000 -t 5
```

Verificación con UDP:

```bash
# en h1
iperf -s -u -p 9001
# en h2
iperf -c 200.0.0.1 -p 9001 -u -t 5
```

La tabla de traducción se puede observar en el log del controlador: cada
conexión aparece como un registro de la forma
`TCP 192.168.1.2:puerto -> 200.0.0.254:puerto_público <-> 200.0.0.1:9000`.
También se puede capturar tráfico con wireshark/tcpdump en cualquier host para
ver la traducción de direcciones en ambos sentidos.

## Diseño (resumen)

- **ARP**: el controlador responde requests dirigidas a sus dos IPs, genera
  requests propios para resolver MACs (hosts privados y servidor público) y
  mantiene una tabla ARP dinámica con expiración (5 min). Los paquetes que
  esperan una resolución se encolan y se envían al llegar la respuesta.
- **NAT/PAT**: cada conexión se describe con un registro
  `(proto, IP priv, puerto priv, IP remota, puerto remoto) → puerto público`,
  indexado en ambos sentidos. Los puertos públicos se asignan de un rango
  efímero evitando colisiones (por protocolo) y se liberan al expirar el
  registro. ICMP echo se traduce por identificador.
- **Flujos**: al establecerse una conexión se instalan dos reglas exactas
  (saliente y entrante) con acciones `SET_NW_SRC/DST`, `SET_TP_SRC/DST` y
  `SET_DL_SRC/DST`, con `idle_timeout=10` y `hard_timeout=60` s. El
  controlador solo interviene ante conexiones nuevas, ARP o expiraciones.
- **Sin hardcodeo de MACs/IPs de hosts**: el controlador descubre las MACs por
  ARP; se puede cambiar la IP del servidor o las MACs de los hosts y la
  solución sigue funcionando.

## Documentación

- Enunciado: `docs/TP2_NAT_jueves.pdf`
- Informe: `docs/informe.tex` (compilar con `docs/build.sh` o `docs/build.ps1`)

### Documentación de POX:
https://noxrepo.github.io/pox-doc/html/