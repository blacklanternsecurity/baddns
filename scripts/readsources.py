#!/usr/bin/env python3

import os

directory = './dnsReaper/signatures'

files = os.listdir(directory)
for filename in files:
	print(filename)
       
