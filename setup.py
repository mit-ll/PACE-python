#!/usr/bin/env python
## **************
##  Copyright 2015 MIT Lincoln Laboratory
##  Project: PACE
##  Authors: SS
##  Description: Installation file for PACE.  Run by entering "python setup.py install" in terminal
##  Modifications:
##  Date         Name  Modification
##  ----         ----  ------------
##  06 Oct 2015  SS    Original file
##  19 Nov 2015  SS    Added dependencies
## **************

from setuptools import setup, find_packages
import os.path

VERSION = '1.3'
README = 'README.md'

setup(
	# Package name, version, and short description
	name='pace',
	version=VERSION,
	description='Proactively-Secure Accumulo with Cryptographic Enforcement',

	# Long description is the README
	long_description=open(os.path.join(os.path.dirname(__file__), README)).read(),

	# Author details
	author='MIT Lincoln Laboratory',
	author_email='pace-contact@ll.mit.edu',

	# License and online information commented out until open-sourcing
	#license='',
	#url='',
	#keywords='',
	
	# Recursively find all packages (folders containing __init__.py files) in the pace directory
	packages=find_packages(), 

	# Dependencies that can be automatically installed.
	# Note that there are some dependencies that must be manually installed.
	# They can be installed using install.sh or by checking the dependency
	# list in the README and downloaded manually.
	install_requires=[
		'Beaker>=1.7.0',
		'enum34>=1.0.4',
		'nose>=1.1.2',
		'pyaccumulo>=1.5.0.6',
		'distribute>=0.6.14',
		],
)			  

