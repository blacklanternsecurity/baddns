#!/usr/bin/env python3

import os

#directory = './punk-security/dnsReaper/signatures'
directory = "."

files = os.listdir(directory)

for filename in files:
	print(filename)
       
