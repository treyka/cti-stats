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
6. Configure a temporary account on your CTI repository (Soltra Edge
   or whatever. which is authorized to poll your entire repository.
7. Review cti-stats usage: `./cti-stats --help`
8. Run cti-stats, passing the appropriate arguments depending on your
   environment
   * Certain parameters have defaults if not otherwise specified.
     Refer to the output of `./cti-stats --help` for clarification.
   * For an example, to run cti-stats against
     [Hail a TAXII](http://hailataxii.com): 
     `./cti-stats --user=guest --pass='guest' --host=hailataxii.com
     --port=80 --use-ssl=False --validate-cert=False --stats`
9. Depending on the quantity of CTI data in your repository, you might
   have to wait a while for the results to be computed so go make a
   cup of coffee or work on something else while this runs in the
   background.
10. Eventually, you should get some output that looks like this:
11. Send the output to one or more of the OASIS CTI co-chairs:
    * [Trey Darley](mailto:trey@soltra.com)
    * [Ivan Kirillov](mailto:ikirillov@mitre.org)
    * You may opt to omit the total counts info for confidentiality
      reasons but at least send us the percentages!
```+-------STIX stats------------------------------------------------------+
+-------STIX percentages------------------------------------------------+
ttps: 6.00%
indicators: 93.00%
+-------STIX counts-----------------------------------------------------+
ttps: 62
indicators: 914
Total STIX objects: 976

+-------CybOX stats-----------------------------------------------------+
+-------CybOX percentages-----------------------------------------------+
DomainName: 100.00%
+-------CybOX counts----------------------------------------------------+
DomainName: 914
Total CybOX objects: 914
```
