# The story of a ransomware builder: from Thanos to Spook and beyond (Part 1)

During an onsite incident response analysis, CERT-Sekoia was contacted in order to respond to a Spook ransomware attack. A further analysis on Thanos builder and how obfuscation is implemented.

[Link to the article]()

# Script

## Usage

```
usage: deobfuscate.py [-h] [-r RID] [-i INTEGER] [-d DATA] [-f FILTER] [-c CONFIG] input

Decrypt resource file from spook sample

positional arguments:
  input                 Resource File

optional arguments:
  -h, --help            show this help message and exit
  -r RID, --rid RID     RID of the class
  -i INTEGER, --integer INTEGER
                        Integer value to decode
  -d DATA, --data DATA  File contianing rid followed by a list of integer to decode (json)
  -f FILTER, --filter FILTER
                        Filter print value for a data file
  -c CONFIG, --config CONFIG
                        config file including key, IV, offset and xor_value for a specific resource file
```

## Installation

You need to install python3 packages located in requirements file. The script has been tested on python version > 3.8.

```
pip install -r requirements.txt
```

# Contributors

CERT-SEKOIA
