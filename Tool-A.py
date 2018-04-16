#!/usr/bin/env python

"""
The MIT License (MIT)

Copyright (c) 2018 Hardiyano Agparys <mukabelakang86@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Softwa

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

__author__ = "Hardiyanto (Bal4uRinNG)"
__homepage__ = "https://kawarokong.blogspot.com"
__github__ = "https://github.com/Hardiyano16/hasher"


from re import search
from os import mkdir, path, system
from sys import argv, platform
from time import strftime
from requests import post


BANNER = """\033[01;36m\
______            __      ___
 /_  __/___  ____  / /     /   |
  / / / __ \/ __ \/ /_____/ /| |
 / / / /_/ / /_/ / /_____/ ___ |
/_/  \____/\____/_/     /_/  |_|\033[0m
                                                
[#] Tool-A Analyzer Tool
[#] Created By %s
[#] %s\n
""" % (__author__,__homepage__)


def clearScreen():
	if platform == "win32":
		system("cls")
	else:
		system("clear")
		
		
def makeOutput(outfile):
	dir = "output/"
	if not path.isdir(dir):
		mkdir(dir)
	output = open(dir + outfile, "a")
	return output
	
	
def hash_analyzer(hash, outfile):
	print ("\n[*] Analyzing hash: %s ..." % hash)
	output = makeOutput(outfile)
	msg = "[+] Hash: %s" % hash; output.write(msg + "\n")
	url = "http://crackhash.com/hash_analyzer.php"
	data = {
		"hash": hash,
		"find":"Find"
	}
	response = post(url, data=data)
	htmltext = response.text
	lenght = len(hash)
	if "Hash type :" not in htmltext:
		msg = "[+] Type: unknown"; output.write(msg + "\n")
		print (msg)
		msg = "[+] Lenght: %s" % lenght; output.write(msg + "\n")
		print (msg)
		msg = "---"; output.write(msg + "\n")
		print (msg)
		
	else:
		type = search("Hash type : (.*) <br>", htmltext).group(1)
		msg = "[+] Type: %s" % type; output.write(msg + "\n")
		print (msg)
		msg = "[+] Lenght: %s" % lenght; output.write(msg + "\n")
		print (msg)
		msg = "---"; output.write(msg + "\n")
		print (msg)
		


def run(db, outfile):
	print ("\n[*] Hashzer starting at: %s" % strftime("%X"))
	if path.isfile(db):
		file = open(db, "rb")
		hashdb = file.readlines()
		for hash in hashdb:
			hash = hash.strip("\n")
			if len(hash) != 0:
				space = " "
				if space in hash:
					hash = hash.replace(space, "")
				hash-A_analyzer(hash, outfile)
	else:
		hash_analyzer(db, outfile)
	print ("[*] The result of analysis is stored on %s" % path.abspath("output/"+outfile))
	print ("[*] Hashzer has been completed at: %s\n\n" % strftime("%X"))


TOLONG_AKU = """\
Command             Description
-------             -----------
help                Show this help message
clear               Clear screen

set hash <hash>     Hash (supports to use files) (e.g. hashdb.txt)
set output <name>   Output file name (e.g. hashzer.txt)

show value <var>    Variable must be (hash or output)

find                Starts analyzing hash
exit                Exit program's

"""


hashdb = ""
output = ""


def main():
	global hashdb, output
	while True:
		cmd = raw_input("hashzer> ")
		if cmd == "help":
			print (TOLONG_AKU)
			
		elif cmd == "clear":
			clearScreen()
			print (BANNER)
			main()
			
		elif "set hash" in cmd:
			hashdb = cmd.split()[-1]
		
		elif "set output" in cmd:
			output = cmd.split()[-1]
		
		elif "show value" in cmd:
			var = cmd.split()[-1]
			if var not in ("hash", "output"):
				print ("[!] Variable: %s not found..." % repr(var))
			else:
				print ("[+] %s: %s" % var, eval(var))
			
		elif cmd in ("find","mulai","scan"):
			if hashdb != "":
				if output != "":
					run(hashdb, output)
				else:
					print ("[!] output: (NOT FOUND)")
			else:
				print ("[!] hash: (NOT FOUND)")
				
		elif cmd in ("exit", "q", "keluar"):
			print ("[!] Exiting...")
			exit(1)
		
		else:
			print ("[!] Unknown command: %s..." % repr(cmd))
			main()
			
	
if __name__ == "__main__":
	clearScreen()
	print (BANNER)
	try:
		main()
	except KeyboardInterrupt:
		print ("[!] User stopped!")
	main()
		