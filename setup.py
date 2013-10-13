#!/usr/bin/env python

import os
from setuptools import setup, find_packages

version = '0.1.0'

LONG_DESCRIPTION = '''
A twitter-clone made with Python + Redis (based in http://redis.io/topics/twitter-clone)
'''

setup(
    name                 = 'retwis-py',
    version              = version,
    description          = 'A twitter-clone made with Python + Redis (based in http://redis.io/topics/twitter-clone)',
    long_description     = LONG_DESCRIPTION,
    url                  = 'https://github.com/eduardonunesp/retwis-py',
    author               = 'Eduardo Nunes',
    author_email         = 'eduardonunesp@gmail.com',
    keywords             = 'Redis, Twitter-Clone, Python, Flask',
    license              = 'MIT',
    py_modules           = ['retwis_server'],
    include_package_data = True,
    zip_safe             = False,
    packages             = ['retwis_server'],
    package_dir          = {'retwis_server': 'src'},
    package_data         = {'retwis_server': ['templates/*.html', 'static/css/style.css', 'static/img/*.png']},
    classifiers          = [
    'Programming Language :: Python',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
   ],
)
