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

