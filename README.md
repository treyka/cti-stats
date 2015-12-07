cti-stats
=========

What is it?
===========
* A utility for gathering anonymized metrics about STIX/CybOX object
  usage.

Why?
====
* The OASIS CTI standards technical committees are trying to make
  informed choices about refactoring STIX and CybOX. Unfortunately,
  we're not privy to the vast majority of the relevant data due to the
  confidentiality requirements of the various sharing communities out
  there (ISACs, ISAOs, etc.) The idea is that authorized personnel
  from these various sharing communities can run this utility to
  gather anonymous statistics about STIX/CybOX object usage within
  their group and share that back with the OASIS CTI co-chairs.

How to install it?
==================
1. Clone this repository: `git clone
   https://github.com/Soltra/cti-stats.git`
   * It's recommended that you *do not* run cti-stats on your
     production repository to avoid resource-contention. Of course,
     you're free to point cti-stats at localhost, but it's wiser to
     run it from a different box. (For ideal performance, a box
     collocated in the same network subnet.)
2. `cd cti-stats`
3. Instantiate a Python virtual environment: `virtualenv python_env`
4. Activate the Python virtual environment: `source
   python_env/bin/activate`
5. Install the necessary Python dependencies: `pip install -r
   requirements.txt`

How to run it?
==============
* You have two basic options: polling a TAXII feed or recursing
  through a directory containing CTI.

Polling a TAXII feed
--------------------
1. Configure a temporary account on your CTI repository (Soltra Edge
   or whatever. which is authorized to poll your entire repository.
2. Review cti-stats usage: `./cti-stats --help`
3. Run cti-stats, passing the appropriate arguments depending on your
   environment
   * Certain parameters have defaults if not otherwise specified.
     Refer to the output of `./cti-stats --help` for clarification.
   * In normal mode, a progressbar is displayed. If you want to
     redirect cti-stats output to a file, append `--quiet >
     my_filename` to your command.
   * examples
     * run cti-stats against [Hail a TAXII](http://hailataxii.com): 
     `./cti-stats --user=guest --pass='guest' --host=hailataxii.com
     --port=80 --use-ssl=False --taxii-stats`
     * run cti-stats against a non-ssl TAXII endpoint: `./cti-stats --user=USERNAME --pass='PASSWORD' --host=HOST_OR_IP
     --port=80 --use-ssl=False --taxii-stats`
     * run cti-stats against an ssl TAXII endpoint: `./cti-stats --user=USERNAME --pass='PASSWORD' --host=HOST_OR_IP
     --port=443 --use-ssl=True --taxii-stats`
       * If there's a self-signed certificate on the other end,
         append: `--validate-cert=False`
     * If two-way ssl authentication is enabled, append: `--ssl-cert=MY_CERT.pem`

Recursing a directory
---------------------
1. Identify a directory containing CTI you wish to analyze.
2. Review cti-stats usage: `./cti-stats --help`
3. Run cti-stats, passing the appropriate arguments depending on your
   environment
   * Certain parameters have defaults if not otherwise specified.
     Refer to the output of `./cti-stats --help` for clarification.
   * In normal mode, a progressbar is displayed. If you want to
     redirect cti-stats output to a file, append `--quiet >
     my_filename` to your command.
   * For an example: `./cti-stats --target-dir=~/cti_sample_data/ --file-stats`


Supported STIX versions
=======================
* cti-stats attempts to support all versions of STIX (1.0, 1.0.1, 1.1,
  1.1.1, and 1.2) via the MITRE
  [stix-ramrod](https://github.com/STIXProject/stix-ramrod) library.
  This works well in testing so far but there's no guarantee that it
  will support all conceivable STIX variants so be warned that your
  mileage may vary.


What to do with your analysis results
=====================================
1. Depending on the quantity of CTI data in your repository, you might
   have to wait a while for the results to be computed so go make a
   cup of coffee or work on something else while this runs in the
   background. In any case, cti-stats prints a progressbar with ETA on
   the console, so even if it takes a long time to run, you at least
   now how the progress is going.
2. Eventually, you should get some output that looks like this:
```
+-------STIX stats------------------------------------------------------+
+-------STIX percentages------------------------------------------------+
ttps: 0.91%
indicators: 99.09%
+-------STIX counts-----------------------------------------------------+
ttps: 3442
indicators: 374645
Total STIX objects: 378087

+-------CybOX stats-----------------------------------------------------+
+-------CybOX percentages-----------------------------------------------+
URI: 38.81%
Address: 28.85%
Port: 0.62%
File: 0.30%
DomainName: 31.41%
+-------CybOX counts----------------------------------------------------+
URI: 192292
Address: 142963
Port: 3089
File: 1488
DomainName: 155623
Total CybOX objects: 495455
```
3.  Send the output to one or more of the OASIS CTI co-chairs:
    * [Trey Darley](mailto:trey@soltra.com)
    * [Ivan Kirillov](mailto:ikirillov@mitre.org)
    * You may opt to omit the total counts info for confidentiality
      reasons but at least send us the percentages!
    * Ivan and I will be sharing the datasets within the OASIS CTI
      community *however* we will be anonymizing the names of the
      organizations who've provided us with stats.
