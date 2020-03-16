from setuptools import setup, find_packages

setup(
    name='cert-check',
    version='0.3.6',
    url='https://github.com/HQJaTu/cert-check',
    license='GPLv2',
    author='Jari Turkia',
    author_email='jatu@hqcodeshop.fi',
    description='Library and CLI-tool to verify a X.509 certificate validity',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: System Administrators',

        # Specify the Python versions you support here.
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
    python_requires='>=3.7, <4',
    install_requires=['PySSL', 'pyOpenSSL', 'requests', 'cryptography>=2.8', 'pyasn1', 'aiohttp'],
    scripts=['cert-check.py'],
    packages=find_packages()
)
