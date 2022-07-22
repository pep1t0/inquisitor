# inquisitor
ARP spoofing &amp; sniffing 




  _____                   _     _ _             
 |_   _|                 (_)   (_) |            
   | |  _ __   __ _ _   _ _ ___ _| |_ ___  _ __ 
   | | | '_ \ / _` | | | | / __| | __/ _ \| '__|
  _| |_| | | | (_| | |_| | \__ \ | || (_) | |   
 |_____|_| |_|\__, |\__,_|_|___/_|\__\___/|_|   
                 | |                            
                 |_|                            

Coded by daniel.requena@aol.com (2022)
42 Barcelona

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
