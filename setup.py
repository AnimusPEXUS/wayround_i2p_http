#!/usr/bin/python3

from setuptools import setup

setup(
    name='wayround_org_http',
    version='0.3',
    description='http realisation',
    author='Alexey Gorshkov',
    author_email='animus@wayround.org',
    url='https://github.com/AnimusPEXUS/wayround_org_http',
    packages=[
        'wayround_org.http'
        ],
    install_requires=[
        'wayround_org_utils >= 1.10'
        ],
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)'
        ]
    )
