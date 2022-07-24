# inquisitor
ARP spoofing &amp; sniffing 

![inquisitor](https://user-images.githubusercontent.com/108338759/180659738-db11679b-f217-4b32-bcd2-09e74bfc7804.png)

usage: inquisitor.py [-h] [-i IFACE] [-v] IP_src IP_target

Inquisitor envenena las tablas ARP de host origen y destino para a continuacion
interceptar las comunicaciones realizadas mediante el protocolo FTP

positional arguments:
  IP_src                IP Host origen
  IP_target             IP Host destino

options:
  -h, --help            show this help message and exit
  -i IFACE, --iface IFACE
                        Interface seleccionado
  -v, --verbose         Muetra todo el trafico interceptado PUERTO 21

