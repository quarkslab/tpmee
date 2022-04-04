#!/usr/bin/env python
 
from setuptools import setup, find_packages
from setuptools.command.install import install

 
with open('requirements.txt') as f:
    requirements = f.read().splitlines()


setup(
    name='tpm_proxy',
    version='0.0.1',
    packages=find_packages(),
    include_package_data = True,
    author="MadSquirrel",
    author_email="bforgette@quarkslab.com",
    description="",
    #long_description_content_type="text/markdown",
    #long_description=open('README.md').read(),
    download_url="",
    url='',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 1 - Planning"
    ],
 
    entry_points = {
        'console_scripts': [
            'tpm_proxy=tpm_proxy:main',
        ],
    },
    install_requires = requirements,
    python_requires='>=3.5'
 
)

