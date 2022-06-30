# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_InfoIP
# Purpose:      SpiderFoot plug-in for creating new modules.
#
# Author:      Iván Domínguez <ivan18dom@gmail.com>
#
# Created:     28/06/2022
# Copyright:   (c) Iván Domínguez 2022
# Licence:     GPL
# -------------------------------------------------------------------------------

from asyncore import read
import re
from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import socket
import portscanner


class sfp_new_module(SpiderFootPlugin):
    # Se especifica de una manera resumida lo que va a hacer el modulo
    meta = {
        'name': "Informacion IP",
        'summary': "Saca informacion de una direccion IP",
        'flags': ["slow", "tool"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]["Crawling and Scanning"],
    }
    # Opciones por defecto.
    opts = {
    }
    # Descripciones de opciones
    optdescs = {
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
        return []

    # Manejar eventos enviados a este módulo
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        # Compruebe si el módulo ya ha analizado los datos de este evento.
        if eventData in self.results:
            return
        self.results[eventData] = True
        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")
        # Una vez que estemos en este estado, regrese inmediatamente.
        if self.errorState:
            return
        ####################################
        #      Insert here the code        #
        ####################################

        try:
            host_name = socket.gethostname()
            host_ip = socket.gethostbyname(host_name)
            print("Hostname :  ", host_name)
            print("IP : ", host_ip)
        except:
            print("Unable to get Hostname and IP")

        evt = SpiderFootEvent(self, event)
        self.notifyListeners(evt)
  

    

# fim