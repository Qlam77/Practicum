#!/usr/bin/python3
from ParseCommands import parseCommands
import os
import socket
import dbus
import uuid
import sys
import time
import bluetooth
from bluetooth import *

class btDevice:
  # initial variables
  btAddr = "00:1A:7D:DA:71:13"
  host = 0
  port = 1
  listenPort = 17 # Control Port under 0x0004 -> protocol desciptor list -> 0x0100 signifies L2CAPP with port 17 as additional argument
  sendPort = 19 # Interrupt Port under 0x000d -> additional protocol desciptor list -> 0x0100 signifies L2CAPP with port 19 as additional argument
  sdp_record = "sdp_record.xml" # file path of the sdp record to laod
  UUID = "00001124-0000-1000-8000-00805f9b34fb" # keyboard uuid as defined on bluetooth assigned numbers
  keyboardName = "Pi_Keyboard"
  
  #initialize the class
  def __init__(self):
    #define constants
    '''
    os.system("hciconfig hci0 up") # set device as a keyboard
    os.system("hciconfig hci0 name " + btDevice.keyboardName)
    os.system("hciconfig hci0 class 0x002540") # set device as a keyboard
    os.system("hciconfig hci0 piscan") # turn on discovery
    '''
    self.scontrol = None
    self.ccontrol = None
    self.sinterrupt = None
    self.cinterrupt = None

    try:
      f = open(btDevice.sdp_record, "r")
      self.service_record = f.read()
    except:
      sys.exit("Could not read SDP file")

    opts = {'Role': 'server',
            'RequireAuthentication': False,
            'RequireAuthorization': False,
            'AutoConnect': True,
            'ServiceRecord': self.service_record
    }

    self.dbus = dbus.SystemBus() # get dbus
    try:
      self.bluzObject = self.dbus.get_object("org.bluez", "/org/bluez") # get the bluez object
      print("Got bluez")
      self.manager = dbus.Interface(self.bluzObject, "org.bluez.ProfileManager1") # get methods from the bluez object
      print("Got interface")
      self.manager.RegisterProfile("/org/bluez/hci0", btDevice.UUID, opts) # use and register sdp onto the profile, use keyboard UUID with additional options
      print("Registered Profile")
    except:
      sys.exit("dbus failed to get bt")
    print("end of init")
    
    print("set command parse object")
    self.commandParser = parseCommands(None)
    
    print("Setting listener")
    #create bt sockets
    self.scontrol = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    self.sinterrupt = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    
    print("Setting socket options")
    #set reuseable addr
    self.scontrol.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.sinterrupt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    print("binding ports")
    #bind
    self.scontrol.bind((btDevice.btAddr, btDevice.listenPort))
    self.sinterrupt.bind((btDevice.btAddr, btDevice.sendPort))
    
    print("listening for connections")
    # setting server listener
    self.scontrol.listen(1)
    self.sinterrupt.listen(1)
    
    # accept connections on both ports
    self.ccontrol, cinfo = self.scontrol.accept()
    print("Listener port got a connection!")
    
    self.cinterrupt, cinfo = self.sinterrupt.accept()
    print("Sender port got a connection!")
    
    print("Update parser object")
    #print(repr(self.sender))
    self.commandParser.setBtDevice(self.cinterrupt)

    #try:
    #  self.sender.send(cmd_str)
    #except Exception as e:
    #  print(e)
    #print("Get ready to swap applications!")
    time.sleep(5)

    print("Parse/reading/sending keystrokes")
    self.commandParser.readCommands()
    
    print("Returned from keyboard function")
    while True:
      print("Sleeping")
      time.sleep(60)

a = btDevice()
