#!/usr/bin/env python

import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
import time 

def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

def nmapScan(ip_address):
   ip_address = ip_address.strip()
   print "INFO: Running general TCP/UDP nmap scans for " + ip_address
   serv_dict = {}
   #sudo nmap --script-updatedb
   #sudo nmap -p- --open -vvv --min-rate 5000 -sS -Pn 10.10.10.4 -oN nmap
   #sudo nmap -sVC -p135,139,445 10.10.10.4 -oN nmap.service
   #sudo nmap -sV -p 443 --script "vuln" 192.168.50.124
   TCPSCAN = "nmap -p- --open -vvv --min-rate 5000 -sS -Pn -oN '%s.nmap' %s"  % (ip_address, ip_address)
   #TCPSCAN = "nmap -vv -Pn -A -sC -sS -T 4 -p- --min-rate 5000 -oN '%s.nmap' %s"  % (ip_address, ip_address, ip_address)
   UDPSCAN = "nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 --min-rate 5000 -oN '%sU.nmap' %s" % (ip_address, ip_address)
   results = subprocess.check_output(TCPSCAN, shell=True)
   #udpresults = subprocess.check_output(UDPSCAN, shell=True)
   lines = results.split("\n")
   port_list = []
   for line in lines:
      ports = []
      line = line.strip()
      if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
	 while "  " in line: 
            line = line.replace("  ", " ");
         linesplit= line.split(" ")
         service = linesplit[2] # grab the service name
	 port = line.split(" ")[0] # grab the port/proto
	 port_list.append(port[:-4])
         if service in serv_dict:
	    ports = serv_dict[service] # if the service is already in the dict, grab the port list
	 
         ports.append(port) 
	 serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
   

   port_scan = ''.join(str(p)+"," for p in port_list)[:-1]
   print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
   SERVICESCAN = "nmap -sVC --script 'vuln' -p%s -oN '%s.service' %s"  % (port_scan, ip_address, ip_address)  
   subprocess.check_output(SERVICESCAN, shell=True)
   print "INFO: Service scan completed for " + ip_address 
   return

# grab the discover scan results and start scanning up hosts
print "############################################################"
print "####                      RECON SCAN                    ####"
print "####            A multi-process service scanner         ####"
print "############################################################"
 
if __name__=='__main__':
   f = open('targets.txt', 'r') 
   for scanip in f:
       jobs = []
       p = multiprocessing.Process(target=nmapScan, args=(scanip,))
       jobs.append(p)
       p.start()
   f.close() 
