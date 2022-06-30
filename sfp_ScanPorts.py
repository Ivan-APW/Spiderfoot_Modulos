# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ScanPorts
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Iván Domínguez <ivan18dom@gmail.com>
#
# Created:     28/06/2022
# Copyright:   (c) Iván Domínguez 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

#import re
#import json
from urllib.request import urlopen
from netaddr import IPNetwork
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import nmap
import sys


class sfp_new_module(SpiderFootPlugin):
    # Se especifica de una manera resumida lo que va a hacer el modulo
    meta = {
        'name': "ScanPorts",
        'summary': "Escanea los puertos de una direcion IP y su localización",
        'flags': ["slow", "tool"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]["Crawling and Scanning"],
        # Detalles de la aplicacion que se va a utilizar
        'toolDetails': {
            'name': "nmap",
            'description': "Detailed descriptive text about the tool",
            'website': 'https://nmap.org/',
            'repository': 'https://github.com/nmap/nmap'
        },
    }
    # Opciones por defecto.
    opts = {
    }
    # Descripciones de opciones
    optdescs = {
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
    }
    # El seguimiento de los resultados puede ser útil para evitar reportar/procesar duplicados
    results = None
    # Para saber cuando a fallado el modulo
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]
    # ¿En qué eventos está interesado este módulo para la entrada?

    def watchedEvents(self):
        return ["IP_ADDRESS"]
    # Qué eventos produce este módulo

    def producedEvents(self):
        return ['GEOINFO', 'VULNERABILITY_GENERAL']

    # Manejar eventos enviados a este módulo
    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data
        # Una vez que estemos en este estado, regrese inmediatamente.
        if self.errorState:
            return
         # Compruebe si el módulo ya ha analizado los datos de este evento.
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return
        # Agregue los datos del evento al diccionario de resultados para evitar consultas duplicadas.
        self.results[eventData] = True
        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            net_size = IPNetwork(eventData).prefixlen
            if net_size < max_netblock:
                self.debug(
                    f"Network size {net_size} bigger than permitted: {max_netblock}")
                return
        # Direcciones IP para buscar
        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
        for addr in qrylist:
            rec = self.query(addr)
            # Manejar que la respuesta esté vacía/falla
            if rec is None:
                continue
        ####################################
        #      Insert here the code        #
        ####################################
        
        #Localizar IP
        try:
            #Pegando ip informado como argumento.
            ip=sys.argv[1]
            if ip:
                #URL do apt
                url=f"http://ip-api.com/json/{ip}"
                #Iniciandoorequest
                request=urlopen(url)
                data=request.read().decode()
                #Convertendo string api,pora DICT(Dicionário)
                data=eval(data)
                for i in data:
                    print(f"(i)(data[1])")
        except Exception as ex:
            print("Error:(ex)")
        
        # Escanear vulnerabilidades
        ip = input("[+] IP Objetivo ==> ")
        nm = nmap.PortScanner()
        puertos_abiertos = "-p "
        results = nm.scan(hosts=ip, arguments="-sT -n -Pn -T4")
        count = 0
        #print (results)
        print("\nHost : %s" % ip)
        print("State : %s" % nm[ip].state())
        for proto in nm[ip].all_protocols():
            print("Protocol : %s" % proto)
            print()
            lport = nm[ip][proto].keys()
            sorted(lport)
            for port in lport:
                print("port : %s\tstate : %s" % (port, nm[ip][proto][port]["state"]))
                if count == 0:
                    puertos_abiertos = puertos_abiertos+str(port)
                    count = 1
                else:
                    puertos_abiertos = puertos_abiertos+","+str(port)
            print("\nPuertos abiertos: " + puertos_abiertos + " "+str(ip))
# fim
