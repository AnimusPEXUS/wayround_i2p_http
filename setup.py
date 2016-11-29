#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_i2p_http',
    version='0.7',
    description='http realisation',
    author='Alexey Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_i2p_http',
    packages=[
        'wayround_i2p.http'
        ],
    install_requires=[
        'wayround_i2p_utils'
        ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
        ]
    )
