try:
    from setuptools import setup
except:
    from distutils.core import setup
import zipfile
import os
import pwd

setup(name='smmp',
      version='0.2.2',
      description='Python implementation of the SMMP protocol',
      author='David R. Andersen',
      url='none',
      py_modules=['smmp'],
      install_requires=['python-gnupg >= 0.3.5', 'passlib >= 1.6.1'],
     )
