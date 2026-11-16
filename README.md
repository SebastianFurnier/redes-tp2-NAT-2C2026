# TP2: SDN — NAT saliente con PAT (POX + Mininet)

Implementación de un **NAT saliente con traducción por puertos (PAT)** como
aplicación SDN: la lógica de traducción corre en un controlador **POX**
(`ext/protorouter.py`), que instala reglas **OpenFlow** en un switch de
**Mininet** (`topo.py`) para que el forwarding posterior se haga íntegramente
en el plano de datos.

## Topología

```
                         port 1                     port 2
   ┌───────┐  IP: 200.0.0.254    /\  IP: 192.168.1.254      ┌───────┐
   │  h1   ├───────────────────/ s1 \───────────────────────│  h2   │
   └───────┘                   \    /                       └───────┘
200.0.0.1/24                    \  /                    192.168.1.2/24
DG: 200.0.0.254                  \/(port 3)              DG: 192.168.1.254
   Red pública                        ┌───────┐            ┌───────┐
                                      │  h3   │            │  h4   │
                                      └───────┘            └───────┘
                                  192.168.1.3/24       192.168.1.4/24
                                  DG: 192.168.1.254     DG: 192.168.1.254
                                  Red privada
```

- **h1**: host en la red pública (servidor).
- **h2, h3, h4**: hosts en la red privada (clientes). Comparten la única IP
  pública del NAT (`200.0.0.254`) y pueden mantener conexiones simultáneas.
- **s1**: switch OpenFlow controlado por POX; el controlador lo hace actuar
  como router L3 con dos interfaces:

  | Interfaz  | IP            | MAC                   |
  |-----------|---------------|-----------------------|
  | Pública   | 200.0.0.254   | `00:00:00:aa:aa:aa`   |
  | Privada   | 192.168.1.254 | `00:00:00:bb:bb:bb`   |

No hay entradas ARP estáticas en ningún host: toda la resolución de MACs se
hace con el protocolo ARP, manejado por el controlador.

## Ejecución

### Requisitos

- Python 3
- Mininet (entorno Linux — usar VM, WSL2 o máquina Linux)
- POX (incluido en este repositorio, en `pox/`)

### Ejecución del controlador

Desde la raíz del repositorio, ejecutar:

```bash
python3 pox.py log.level --DEBUG openflow.of_01 --port=6653 protorouter
```

>`openflow.of_01 --port=6653`: POX escucha por defecto en el puerto 6633 y 
el `RemoteController` de Mininet se conecta al **6653**, así que hay que pedirlo 
explícitamente (si no, el switch nunca se conecta).
> El módulo `protorouter` vive en `ext/`, que POX agrega solo al *path*, por
> eso se arranca como `protorouter` y no como `ext.protorouter`.

#### Parámetros del controlador

Todos son opcionales; sin ellos valen los de la topología de `topo.py`. Se
validan al arrancar (IPs dentro de su subred, subredes que no se superpongan,
rangos, etc.) y el log muestra la configuración efectiva.

| Parámetro                        | Por defecto                          | Significado                            |
|----------------------------------|--------------------------------------|----------------------------------------|
| `--public_ip` / `--public_mac`   | `200.0.0.254` / `00:00:00:aa:aa:aa`  | interfaz pública del router            |
| `--public_subnet`                | `200.0.0.0/24`                       | red pública (con máscara)              |
| `--public_port`                  | `1`                                  | puerto del switch hacia la red pública |
| `--private_ip` / `--private_mac` | `192.168.1.254` / `00:00:00:bb:bb:bb`| interfaz privada del router            |
| `--private_subnet`               | `192.168.1.0/24`                     | red privada (con máscara)              |
| `--port_min` / `--port_max`      | `10000` / `65535`                    | rango de puertos públicos del NAT      |
| `--flow_idle_timeout`            | `10`                                 | s sin tráfico para que venza una regla |
| `--flow_hard_timeout`            | `60`                                 | s de vida máxima de una regla          |
| `--pending_timeout`              | `5`                                  | s de espera de una respuesta ARP       |
| `--arp_timeout`                  | `10`                                 | s de vida de una entrada ARP           |

Ejemplo con otra red:

```bash
python3 pox.py log.level --DEBUG openflow.of_01 --port=6653 protorouter \
    --public_ip=10.0.0.254 --public_subnet=10.0.0.0/24 \
    --private_ip=172.16.0.254 --private_subnet=172.16.0.0/16 \
    --flow_idle_timeout=5
```

> `topo.py` imprime al arrancar el comando de POX que corresponde a los
> valores de su tabla, para copiarlo tal cual.

### Ejecución de la topología

En otra terminal, ejecutar:

```bash
sudo python3 topo.py
```
#### Cambiar la topología

Las IPs, MACs y la cantidad de hosts se definen en la tabla del principio de
`topo.py` (`ROUTER`, `PUBLIC_HOST`, `PRIVATE_HOSTS`); el resto del archivo no
se toca:

```python
PRIVATE_HOSTS = [
    ('h2', '192.168.1.2', '00:00:00:00:00:02'),
    ('h3', '192.168.1.3', '00:00:00:00:00:03'),
    ('h4', '192.168.1.4', '00:00:00:00:00:04'),
    ('h5', '192.168.1.5', '00:00:00:00:00:05'),   # host nuevo = fila nueva
]
```

Si se cambia algo de `ROUTER` (IP/MAC/subred del router), el controlador tiene
que arrancar con los mismos valores: usar el comando que imprime `topo.py`.
Cambiar solo IPs/MACs de hosts no requiere tocar el controlador (las MACs se
aprenden por ARP). `topo.py` valida la tabla (IPs repetidas, hosts fuera de su
subred, etc.) antes de levantar la red.

### Orden de ejecución recomendado

1. Iniciar el controlador POX.
2. Ejecutar la topología en Mininet.
3. Verificar que el switch se conecte al controlador.

### Verificación básica

Desde la CLI de Mininet:

```bash
mininet> h2 ping -c 3 200.0.0.1
mininet> h3 ping -c 3 200.0.0.1
mininet> h4 ping -c 3 200.0.0.1
```

## Pruebas unitarias

Desde la raíz del repositorio:

```bash
python -m unittest tests.unit.router_config_test
```
Cubren la validación de los parámetros, que el router use la configuración
recibida (redes, puerto público, timeouts, rango de puertos NAT) y los casos
de vencimiento (inactividad, hard timeout, una sola regla vencida, registros
sin reglas, ping).

```bash
python -m unittest tests.unit.protorouter_test
```

Cubren la clasificación de paquetes (saliente / entrante / otro), la
traducción de IP y puertos en ambos sentidos para TCP, UDP y ping, el descarte
de tráfico sin registro NAT, las dos reglas OpenFlow instaladas por conexión y
el reenvío del primer paquete ya traducido.

## Pruebas de NAT con múltiples conexiones (TCP/UDP)

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
También se puede capturar tráfico con Wireshark o `tcpdump` en cualquier host
para ver la traducción de direcciones en ambos sentidos.

### Prueba de vencimiento

Con `--flow_idle_timeout=5` para que sea rápido:

```bash
mininet> h2 ping -c 3 200.0.0.1
mininet> sh ovs-ofctl dump-flows s1          # hay 2 reglas
# esperar 6 s sin tráfico
mininet> sh ovs-ofctl dump-flows s1          # ya no hay reglas
# en el log de POX: "Vencimiento por inactividad: puerto público ... liberado"
mininet> h2 ping -c 3 200.0.0.1              # se reinstalan las reglas
```

## Diseño

- **Clasificación**: cada paquete IPv4 se clasifica como *saliente* (origen
  privado, destino fuera de la red privada), *entrante* (de afuera hacia la IP
  pública) u *otro*, que se descarta.
- **NAT/PAT**: cada conexión se describe con un registro
  `(proto, IP priv, puerto priv, IP remota, puerto remoto) → puerto público`,
  indexado en ambos sentidos. Los puertos públicos se asignan desde el rango
  `[10000, 65535]` reutilizando el puerto original cuando se puede.
- **ICMP (ping)**: se trata como un flujo más, pero **solo se cambia la IP**;
  el identificador de echo se mantiene y la regla se matchea por tipo de ICMP.
- **Flujos**: al establecerse una conexión se instalan dos reglas exactas
  (ida y vuelta) con acciones `SET_NW_SRC/DST`, `SET_TP_SRC/DST` y
  `SET_DL_SRC/DST`, con `idle_timeout=10` y `hard_timeout=60` s. El
  controlador solo interviene ante conexiones nuevas, ARP y vencimientos.
- **Primer paquete**: el paquete que disparó la conexión se reenvía ya
  traducido, para que no se pierda.
  - **Vencimiento de reglas**: las reglas se instalan con `OFPFF_SEND_FLOW_REM`,
  así que el switch avisa (`FlowRemoved`) cuando una vence. El controlador
  recién toca el registro NAT cuando el switch ya no tiene **ninguna** de las
  dos reglas de la conexión (si una sigue viva, hay tráfico en ese sentido,
  por ejemplo un stream UDP que solo va del servidor al cliente):
  - *Por inactividad* (`idle_timeout`): la conexión terminó, se libera el
    puerto público. Si vuelve a haber tráfico, el primer paquete llega como
    `PacketIn`, se crea el registro de nuevo (con el mismo puerto si sigue
    libre) y se reinstalan las dos reglas.
  - *Por `hard_timeout`*: la conexión puede seguir viva, así que se conserva
    el registro y se reinstalan las reglas enseguida, para que el tráfico no
    pase a resolverse en el controlador.
  - Un registro que no logra instalar sus reglas (ARP sin respuesta)
    se libera tras un `idle_timeout`, porque ninguna regla va a
    vencer para avisar.


### Compilar el informe

Windows (PowerShell):

```powershell
.\docs\build.ps1
```

Linux:

```bash
./docs/build.sh
```

El script detecta un motor de LaTeX instalado (`pdflatex`, `xelatex`,
`lualatex` o `latexmk`), compila `informe.tex` a `informe.pdf` y limpia los
archivos auxiliares. Opciones: `-Engine <motor>` / `--clean` (solo limpiar) /
`-KeepAux` (`--keep-aux`, no borrar auxiliares).
