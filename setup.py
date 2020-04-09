# Software setup, install dependancies
#
# Author: Daniel Crouch
# Date created: March 2020

import os
from pathlib import Path
from setuptools import setup

requirements_path = Path.cwd() / 'requirements.txt'

packages = []
with open(requirements_path) as f:
    packages = [line.rstrip('\n') for line in f]

setup(name="ares",
      version='1.0',
      description='Automated Recon and Exploit Software',
      install_requires=packages,
      author = "Daniel Crouch")
