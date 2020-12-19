#!/usr/bin/env python3
import json
import os
import sys

from scanmanager import ScanManager

debug_mode = True

def PrintUsage():
	'''Prints usage information'''
	print(f"Usage: {os.path.basename(sys.argv[0])} [-j] <file1> [<file2>...]\n"
		"Prints phishing threat level for one or more files. Use -j for JSON output.")
	sys.exit(0)

def ScanFilesJSON(pathlist : list):
	'''Scans the list of files and prints threat info about each one in JSON format.'''
	scanner = ScanManager()

	out = list()
	for path in pathlist:
		out.append(scanner.scan(path))

	print(json.dumps(out, indent='\t'))	


if __name__ == '__main__':
	if debug_mode:
		scriptdir = os.path.dirname(os.path.realpath(__file__))
		os.chdir(scriptdir)
		ScanFilesJSON(['README.txt','scanmanager.py'])

	if len(sys.argv) < 2:
		PrintUsage()
	
	# if sys.argv[1] == '-j':
	# 	ScanFilesJSON(sys.argv[2:])
	# else:
	# 	ScanFiles(sys.argv[1:])
