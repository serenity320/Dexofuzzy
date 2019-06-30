Dalvik EXecutable Opcode Fuzzy(Dexofuzzy) Hash
==============================================
Dexofuzzy is a similarity digest hash for Android. It extracts Opcode Sequence from Dex file based on Ssdeep and generates hash value that can be used for similarity comparison of Android App. Dexofuzzy created using Dex's opcode sequence can find similar apps by comparing hash values. 

.. image:: https://img.shields.io/badge/license-GPLv2%2B-green.svg
    :target: https://github.com/ESTsecurity/Dexofuzzy
    :alt: License

.. image:: https://img.shields.io/badge/pypi-v3.3-blue.svg
    :target: https://github.com/ESTsecurity/Dexofuzzy
    :alt: Latest Version

.. image:: https://img.shields.io/badge/python-3%20%7C%203.4%20%7C%203.5%20%7C%203.6%20%7C%203.7-blue.svg
    :target: https://pypi.python.org/pypi/ssdeep/
    :alt: Python Versions


Requirements
------------
Dexpfuzzy requires the following modules:

* ssdeep 3.3  or later


Install
-------

Install on CentOS 7
...................

.. code-block:: console

    $ yum install ssdeep ssdeep-devel
    $ pip3 install dexofuzzy

Install on Ubuntu 14.04, 16.04, 18.04
.....................................

.. code-block:: console

    $ apt-get install libffi-dev libfuzzy-dev
    $ pip3 install dexofuzzy

Install on Windows 10
.....................

* The ssdeep DLL binaries for Windows are included in the ./dexofuzzy/bin/ directory.

.. code-block:: console

    $ pip3 install dexofuzzy

Usage
-----

::

   usage: dexofuzzy [-h] [-o] [-m] [-f SAMPLE_FILE] [-d SAMPLE_DIR] [-c CSV]
                    [-j JSON]

   Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash v0.0.2

   optional arguments:
     -h, --help                     show this help message and exit
     -o, --output-dexofuzzy         extract the dexofuzzy of the sample
     -m, --methodfuzzy              extract the fuzzyhash based on method of the sample
     -f SAMPLE_FILE, --sample-file  SAMPLE_FILE the sample to extract dexofuzzy
     -d SAMPLE_DIR, --sample-dir    SAMPLE_DIR the directory of samples to extract dexofuzzy
     -c CSV, --csv CSV              output as CSV format
     -j JSON, --json JSON           output as json format

Output Format Example
.....................
* *FileName, FileSha256, FileSize, CodeHash, Dexofuzzy*

.. code-block:: console

    $ dexofuzzy -o -f Trojan.Android.SmsSpy.apk 
    Trojan.Android.SmsSpy.apk,80cd7786fa42a257dcaddb44823a97ff5610614d345e5f52af64da0ec3e62835,42959,94d36ca47485ca4b1d05f136fa4d9473bb2ed3f21b9621e4adce47acbc999c5d,48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q
    Running Time : 0.016620635986328125


Python API
..........
To compute a dexofuzzy, use ``hash`` function:

.. code-block:: pycon

    >>> import dexofuzzy
    >>> hash1 = dexofuzzy.hash('APK_FILE_PATH')
    >>> hash1
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> hash2 = dexofuzzy.hash('APK_FILE_PATH')
    >>> hash2
    '48:B2KmUCNc2FuGgy9fbdD7uPrEMc0HZj0/zeGn5:B2+Cap3y9pDHMHZ4/zeG5'

The ``compare`` function returns the match between 2 hashes, an integer value from 0 (no match) to 100.

.. code-block:: pycon

    >>> dexofuzzy.compare(hash1, hash2)
    50


Tested on
---------

* CentOS 7
* Ubuntu 14.04, 16.04, 18.04
* Windows 10

License
-------

Copyright (C) 2019 ESTsecurity.

This project is licensed under the GNU General Public License v2 or later (GPLv2+). Please see  `LICENSE <https://github.com/ESTsecurity/Dexofuzzy/blob/master/LICENSE>`__ located at the project's root for more details.



.. _Dexofuzzy - Android Malware Similarity Clustering Method Using Opcode Sequence: https://www.estsecurity.com/
