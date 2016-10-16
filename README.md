# Nessus Scripts
A (soon to be) suite of python scripts to interact with the Nessus API.


## nessus-download-scans.py
A python script to download completed nessus scans using the python requests library.

### Usage
Specify the username/password and IP/port of the nessus server. One or more output formats can be specified using the `--format` flag. Files are saved to the current working directory.


	~$ nessus-download-scans.py -h
	usage: nessus-download-scans.py [-h] -u USER [-s SERVER] [-p PORT]
	                                [-f {nessus,html,csv,pdf} [{nessus,html,csv,pdf} ...]]
	
	Download Nessus scans.
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -u USER, --user USER  Nessus user instead of API key (password prompt will
	                        occur)
	  -s SERVER, --server SERVER
	                        IP address of Nessus server
	  -p PORT, --port PORT  port number of Nessus server
	  -f {nessus,html,csv,pdf} [{nessus,html,csv,pdf} ...], --format {nessus,html,csv,pdf} [{nessus,html,csv,pdf} ...]
	                        report format

### TODO

 - [ ] Better error handling
