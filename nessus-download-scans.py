#!/usr/bin/env python
from __future__ import print_function
import sys
import time
import json
import signal
import getpass
import requests
import argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning  # Suppress insecure ssl warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)       # Suppress insecure ssl warnings

class Scanner(object):
    def __init__(self, ip='127.0.0.1', port='8834', username='', password=''):
        self.nessus_username = username
        self.nessus_ip = ip
        self.nessus_port = port
        self.nessus_password = password
        self.nessus_verify = False
        self.scans = []
        self.token = ''

    def connect(self):
        print('[+] Connecting...', end='')
        r = requests.post(self._url('/session/'), data = {'username':self.nessus_username, 'password':self.nessus_password}, verify=self.nessus_verify)
        self.token = json.loads(r.text)['token'].encode('ascii')
        print('Done')
        return True

    def disconnect(self):
        print('[+] Disconnecting...', end='')
        headers = {'X-Cookie': 'token={}'.format(self.token), 'Content-Type': 'application/json'}
        requests.delete(self._url('/session/'), headers=headers, verify=self.nessus_verify)
        print('Done')
        return True

    def get_scans(self):
        headers = {'X-Cookie': 'token={}'.format(self.token), 'Content-Type': 'application/json'}
        r = requests.get(self._url('/scans/'), headers=headers, verify=self.nessus_verify)
        scans = r.json()
        s = {}
        for scan in scans['scans']:
            s[str(scan['id'])] = scan['name']
        return s

    def download_scans(self, scans_list, output_format, chapters='vuln_hosts_summary'):
        for scan_id in scans_list:
            print('[+] Downloading scan "{}" in "{}" format. '.format(scan_id, output_format), end='')
            
            # Request the file
            headers = {'X-Cookie': 'token={}'.format(self.token)}
            r = requests.post(self._url('/scans/{}/export'.format(scan_id)), headers=headers, data={'format':output_format,'chapters':chapters}, verify=False)
            file_id = r.json()['file']
            
            # Download the File
            while True:
                r = requests.get(self._url('/scans/{}/export/{}/download?token={}'.format(scan_id, file_id, self.token)), verify=False)
                if r.status_code == 409:
                    time.sleep(1.5)
                    continue
                else:
                    filename = r.headers['Content-Disposition'].split('"')[1]
                    with open(filename, "wb") as f:
                        f.write(r.content)
                    f.close()
                    print('Done')
                    break
            
        return True

    def _url(self, path):
        return 'https://{}:{}{}'.format(self.nessus_ip, self.nessus_port, path)

def main(argv):
    parser = argparse.ArgumentParser(description='Download Nessus scans.')
    parser.add_argument('-u', '--user', help='Nessus user instead of API key (password prompt will occur)', required=True)
    parser.add_argument('-s', '--server', help='IP address of Nessus server', default='127.0.0.1')
    parser.add_argument('-p', '--port', help='port number of Nessus server', default='8834')
    parser.add_argument('-f', '--format', help='report format', choices=['nessus', 'html', 'csv', 'pdf'], nargs='+', default='csv')
    args = parser.parse_args()

    passwd = getpass.getpass('Password:')

    scan = Scanner(args.server, args.port, args.user, passwd)
    scan.connect()
    
    ## List Scans
    scans_list = scan.get_scans()
    print('{:^10}{:^20}'.format('Scan ID','Scan Name'))
    print('{} {}'.format('-'*9, '-'*19))
    for k, v in scans_list.iteritems():
        print('{:^10}{:^20}'.format(k, v))
    
    
    ## Choose scans to download
    while True:
        selected_scans = raw_input('Enter Scan ID to download (A for all scans): ')
        selected_scans = selected_scans.lower().strip()

        if selected_scans == 'all' or selected_scans == 'a':
            for k in scans_list:
                scan.scans.append(str(k))
            break
        if selected_scans == '':
            print('Please enter a value')
            continue
        for s in selected_scans.split(','):
            s = s.strip()
            if s.isdigit():
                if s not in scans_list:
                    break
                scan.scans.append(s)
            else:
                break
        else:
            break
        print('One or more the the inputted values are invalid')

    # Download Scans
    for f in args.format:
        scan.download_scans(scan.scans, f)

    scan.disconnect()

def signal_handler(signal, frame):
        # Ctrl+C
        print('\nGoodbye')
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv)


# https://cloud.tenable.com/api#/resources/scans/export
# https://community.tenable.com/docs/DOC-1172