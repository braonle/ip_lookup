# About
The script resolves IPs to some information, provided by Regional Internet Registries (RIR),
and FQDN, if possible, for two use cases:
1. list of IPs is provided in text file; output can be either JSON or Excel spreadsheet
1. IPs within CSE SSL spreadsheet are to be resolved.

This unofficial script is provided AS-IS, use it at your own risk.

## Setup the environment

To avoid conflicts between different modules we'll use Python virtual environment:

```shell
$ cd ip_lookup
$ chmod +x resolve.py      # enable running without explicit python cmd
$ python -m venv venv
$ source venv/bin/activate
(venv) $
```

After venv is setup, you'll need to install the requirements.

```shell
(venv) $ pip install --upgrade pip
(venv) $ pip install -r requirements.txt
```

# Usage
IP cache timeout is set to 14 days by default.

## Python venv

Enable virtual environment scope:
```shell
$ source venv/bin/activate
(venv) $ 
```

Different scripts could be run in different windows and thus in different venv, however, 
venv can be disabled as well:
```shell
(venv) $ deactivate
$ 
```

## Options

By default the tool searches for the latest relevant file, if a corresponding parameter is provided
without value.

```shell
(venv) $ ./resolve.py --help
usage: resolve.py [-h] [-l [FILE]] [-c FILE] [-x [FILE]] [--excel-export [FILE]] [--json-export [FILE]]

Resolve IP addresses into RIR info and FQDN

options:
  -h, --help            show this help message and exit
  -l [FILE], --list [FILE]
                        filename for the list of IP addresses; latest .txt used by default
  -c FILE, --cache FILE
                        cache filename; 'ip_networks_cache.json' is used by default
  -x [FILE], --excel [FILE]
                        CSE SSL spreadsheet filename; latest .xlsx sed by default
  --excel-export [FILE]
                        Export data to Excel
  --json-export [FILE]  Export data to JSON
```

### Running lookup for IP list in text file and JSON output
```shell
(venv) $  ./resolve.py -l --json-export
04/06/2024 13:51:11 [resolve:61] [INFO] Resolving IPs from text file ip.txt
04/06/2024 13:51:15 [lookup:221] [INFO] Sleeping 2 seconds after another 10 lookups. Total lookups: 10
04/06/2024 13:51:20 [lookup:237] [INFO] cache_hits=4 | lookups=19
04/06/2024 13:51:20 [resolve:66] [INFO] Saving IPs from text file to JSON out.json
04/06/2024 13:51:20 [resolve:83] [INFO] Script ran for 0:00:09.186392 seconds.
```

### Running lookup for IP list in text file and Excel output
```shell
(venv) $  ./resolve.py -l --excel-export
04/06/2024 13:52:13 [resolve:61] [INFO] Resolving IPs from text file ip.txt
04/06/2024 13:52:13 [lookup:237] [INFO] cache_hits=23 | lookups=0
04/06/2024 13:52:13 [resolve:75] [INFO] Saving IPs from text file to Excel out.xlsx
04/06/2024 13:52:13 [resolve:83] [INFO] Script ran for 0:00:00.031317 seconds.
```

### Running lookup for SSL inspection spreadsheet
Changes are saved inline in the spreadsheet provided.

```shell
(venv) $  ./resolve.py -x
04/06/2024 13:57:00 [resolve:79] [INFO] Resolving IPs from CSE SSL spreadsheet ZIA_SSL_3M_Company_2024-05-29_12-29-13.xlsx
04/06/2024 13:57:13 [lookup:320] [INFO] Sleeping 2 seconds after another 10 lookups. Total lookups: 10
04/06/2024 13:57:19 [lookup:320] [INFO] Sleeping 2 seconds after another 10 lookups. Total lookups: 20
04/06/2024 13:57:22 [lookup:329] [INFO] cache_hits=12 | lookups=24
04/06/2024 13:57:23 [resolve:83] [INFO] Script ran for 0:00:22.742515 seconds.
```

## Hints
### Pre-modify IP list
The script expects to receive one IP address or network per line. However, in some cases
the list is actually separated by commas. Given the size of the list, it's not feasible to
modify it manually. Some automated tool should replace ", " with a NEWLINE symbol.

Example for MacOS (**\n** is a NEWLINE character, and **-i** instructs tool to perform inline replacement:
```shell
(venv) $ gsed -i "s/, /\n/g" ip.txt
```