import socket
from os import system , name
import sys
import requests
import time
import random
from threading import Thread
import threading as threading


# colors  .. 
Cyan = '\033[1;36;40m'
white = '\033[1;37;40m'
magenta = '\033[1;35;40m'
red = '\033[1;31;40m'
green = '\033[1;32;40m'
yellow = '\033[1;33;40m'


def clear(): 
  
    # for windows 
    if name == 'nt': 
        _ = system('cls') 
  
    # for mac and linux(here, os.name is 'posix') 
    else: 
        _ = system('clear')




def getip():
	# get orginal url to get IP address
	url = raw_input("Enter target url: ")
	if "https://" in url:
		url = url.replace("https://","")
		url = url.replace("/","")
	elif "http://" in url:
		url = url.replace("http://","")
		url = url.replace("/","")

	else:
		pass

	s = socket.gethostbyname(url)
	print "[%s*%s] IP: %s%s%s " % (green,white,green,s,white)


def dir_bruter():
	lives = []
	#brutforce directorys
	print "[*] %sBrutforce Directorys %s" % (Cyan,white)
	print "[%s*%s] %sNote : Please Enter url like this %s( %shttp[s]://example.com/ %s)" % (yellow,white,yellow,white,red,white)
	url = raw_input("[*] Enter target url: ")
	print "[*] %sBrutforcing Directorys .. %s" % (Cyan,white)
	print ""
	directorys = open("directorys","r").readlines()

	for link in directorys:
		link = link.rstrip()
		links = url+link

		r = requests.get(links)
		lives.append(r)
		code = r.status_code
		if code != 404:
			print "[ %s%d%s ] => %s" % (Cyan,code,white,links)
			lives.append(r)
			with open("dir_bruter.txt","a") as bru:
				bru.write(links+"\n")
		else:
			print "[ %s%d%s ] => %s%s%s" % (red,code,white,red,links,white)
			

def admin():
	lives = []
	print "[%s*%s] %sAdmin Finder .. %s" % (magenta,white,magenta,white)
	print "[%s*%s] %sNote : Please Enter url like this %s( %shttp[s]://example.com/ %s)" % (yellow,white,yellow,white,red,white)
	url = raw_input("[*] Enter url : ")
	print ""

	admins = open('admins.txt', 'r').readlines()
	for i in admins:
		i = i.rstrip()
		link = url+i
		links = requests.get(link)
		code = links.status_code
		if code != 404:
			print "%s Found == > %s%s" % (green,link,white)
		else:
			print "%s Not Found %s%s" % (red,link,white)
			lives.append(links)
def port():
	print "[%s*%s] %sPort Checker %s " % (green,white,green,white)
	po = raw_input("""
		[1] [ Defult ]
		[2] [Single port]
		
		@> : """)
	if po == "1": 
		print "[%s*%s] %sChecking ports from 1 to 1000%s" % (green,white,Cyan,white)
		ip = raw_input("[*] Enter host name or ip : ")
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		for por in range(19,1000):

			try:
				s.connect((ip,por))
				s.close()
				print "[%s*%s] Port open == > %d" % (green,white,por)
			except:
				print "[%s*%s] Port Closed == > %d" % (red,white,por)
	elif po == "2":
		ip = raw_input("[*] Enter host name or ip : ")
		port = int(raw_input("[*] Enter port : "))
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((ip,port))
			s.close()
			print "[%s*%s] Port : %d Open" % (green,white,port)
		except:
			print "[%s*%s] Port : %d Closed" % (red,white,port)


def logo():
	clear = "\x1b[0m"
        colors = [31,32,33,36]

        x = """

        

         _
 .---.  / > .---,
  <_  `'  `'  _>
    <_/\  /\_>  
       /`'|
      ".__."
      Saudi Grey Hat Hacker  
  ______            _       _____           _       _   
 |  ____|          | |     / ____|         (_)     | |  
 | |__   __ _  __ _| | ___| (___   ___ _ __ _ _ __ | |_ 
 |  __| / _` |/ _` | |/ _ \___ \ / __|| '__| | '_ \| __|
 | |___| (_| | (_| | |  __/____) | (__| |  | | |_) | |_ 
 |______\__,_|\__, |_|\___|_____/ \___|_|  |_| .__/ \__|
               __/ |                         | |        
              |___/                          |_|        

        author : ./7mD
        Twitter : 0x7mD
        Snapchat : ns_a8 
==================================================== 
    """
        for N, line in enumerate(x.split("\n")):
            sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
            time.sleep(0.05)

def chose():
 	ch = """
 	[1] Get server info
 	[2] Brutforce Directorys
 	[3] Admin Finder
 	[4] Port Checker
 	[5] RCE Finder
 	[6] LFI Finder
 	 """
 	print ch
 	o = raw_input("@>: ")
 	if o == '1':
 		clear()
 		logo()
 		getip()
 	elif o =='2':
 		threads = []
 		clear()
 		logo()
 		t = threading.Thread(target=dir_bruter)
 		t.start()
 		threads.append(t)
 		time.sleep(0.1)
 	elif o =='3':
 		clear()
 		logo()
 		#lives = []
 		b = threading.Thread(target=admin)
 		#lives.append(links)
 		b.start()
 	elif o == '4':
 		clear()
 		logo()
 		port()

 	else:
 		clear()
 		logo()

 		print "BYE BYE :) !!"
def main():
	clear()
	logo()
	chose()
	
main()










