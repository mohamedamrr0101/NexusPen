#!/usr/bin/env python3
"""
NexusPen - Penetration Testing Framework
=========================================
Setup script for package installation.
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "NexusPen - Professional Penetration Testing Framework"

# Read requirements
def read_requirements():
    req_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    requirements = []
    if os.path.exists(req_path):
        with open(req_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Skip packages that may cause issues
                    if 'sqlite3-api' not in line:
                        requirements.append(line)
    return requirements


setup(
    name='nexuspen',
    version='1.0.0',
    author='NexusPen Development Team',
    author_email='nexuspen@example.com',
    description='Professional Penetration Testing Framework',
    long_description=read_readme(),
    long_description_content_type='text/markdown',
    url='https://github.com/nexuspen/nexuspen',
    project_urls={
        'Bug Tracker': 'https://github.com/nexuspen/nexuspen/issues',
        'Documentation': 'https://github.com/nexuspen/nexuspen/wiki',
        'Source': 'https://github.com/nexuspen/nexuspen',
    },
    
    # Package discovery
    packages=find_packages(exclude=['tests', 'tests.*']),
    include_package_data=True,
    
    # Python version requirement
    python_requires='>=3.9',
    
    # Dependencies
    install_requires=read_requirements(),
    
    # Optional dependencies
    extras_require={
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'pytest-asyncio>=0.21.0',
            'black>=23.0.0',
            'flake8>=6.1.0',
            'mypy>=1.5.0',
            'isort>=5.12.0',
        ],
        'docs': [
            'sphinx>=7.0.0',
            'sphinx-rtd-theme>=1.3.0',
            'myst-parser>=2.0.0',
        ],
    },
    
    # Entry points for CLI
    entry_points={
        'console_scripts': [
            'nexuspen=nexuspen:main',
        ],
    },
    
    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
    ],
    
    # Keywords for PyPI
    keywords=[
        'penetration-testing',
        'security',
        'vulnerability-scanner',
        'pentest',
        'ethical-hacking',
        'cybersecurity',
        'web-security',
        'network-security',
    ],
    
    # Package data
    package_data={
        'nexuspen': [
            'config/*.yaml',
            'config/*.json',
            'templates/*.html',
            'templates/*.md',
        ],
    },
    
    # Zip safe
    zip_safe=False,
)
