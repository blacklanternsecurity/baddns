#!/usr/bin/env python3

import os

# Define the directory you want to read files from
directory = './dnsReaper/signatures'

# Get a list of all files in the directory
files = os.listdir(directory)

# Loop through the files
for filename in files:
	print(filename)
       
