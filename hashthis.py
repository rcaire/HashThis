#!/bin/python

# HashThis v0.1
# A basic tool to convert STDIN plain text into a selected hash
# Author: @rcaire 10/10/13

import os,hashlib

def en_md5(txt):
	     """Function to convert plain text to MD5 hash"""
	     text = hashlib.md5(txt).hexdigest()
	     print "-" * 89
	     print "[*] Hash MD5 output: " +  text
	     print "[*] Hash length: " + str(len(text)) + " characters - (128-bits hash value)"
	     print "-" * 89

def en_sha1(txt):
	     """Function to convert plain text to SHA-1 hash"""
	     text = hashlib.sha1(txt).hexdigest()
	     print "-" * 89
	     print "[*] Hash SHA-1 output: " +  text
	     print "[*] Hash length: " + str(len(text)) + " characters - (160-bits hash value)"
	     print "-" * 89

def en_sha256(txt):
             """Function to convert plain text to SHA-256 hash"""
             text = hashlib.sha256(txt).hexdigest()
             print "-" * 89
             print "[*] Hash SHA-256 output: " +  text
             print "[*] Hash length: " + str(len(text)) + " characters - (256-bits hash value)"
             print "-" * 89


def en_sha512(txt):
	     """Function to convert plain text to SHA-512 hash"""
             text = hashlib.sha512(txt).hexdigest()
             print "-" * 89
             print "[*] Hash SHA-512 output: " +  text
             print "[*] Hash length: " + str(len(text)) + " characters - (512-bits hash value)"
             print "-" * 89

def main():
	os.system('clear')
	print ("-" * 36 + "[ HashThis v0.1 ]" + "-" * 36)
	ht = raw_input("[+] Type text to be hashed: ")
	print ""
	print "1- MD5"
	print "2- SHA-1"
	print "3- SHA-256"
	print "4- SHA-512"
	print ""
	selec = raw_input("[+] Choose Hash Algorithm: ")
	print ""	
	if selec == '1':
		en_md5(ht)
	elif selec == '2':
		en_sha1(ht)
	elif selec == '3':
		en_sha256(ht)
	elif selec == '4':
		en_sha512(ht)
	else:
		print "Option error! Try again..."


if __name__ == "__main__":
		try:
		    main()
		except (KeyboardInterrupt, SystemExit):
		    print " Exiting..."
