import os
import sys
import time
import socket
import requests
import ipaddress
import re
import whois
import configparser
from pathlib import Path
import platform
import argparse
import array
import struct
import fcntl
import validators

# Detecting Python 3 for version-dependent implementations
if sys.version_info.major < 3:
    raise Exception("Python's major versions earlier than 3 are not supported!")

# Checking whether it isn't Linux...
if platform.uname().system != 'Linux':
   raise Exception("either your OS nor Kernel is unsupported...")

parser = argparse.ArgumentParser(prog="hosts-generator", description="Generate and Organize Hosts File.")
parser.add_argument('--sfile', type=str, help="Path to Settings file", required=False, metavar='<PATH>')
parser.add_argument('--hfile', type=str, help="Path to local hosts file", required=False, metavar='<PATH>')
parser.add_argument('--efile', type=str, help="Path to new hosts file", required=False, metavar='<PATH>')
parser.add_argument('--afile', type=str, help="Path to remote hosts file", required=False, nargs='*', metavar='<URL>')
parser.add_argument('--dsentry', type=str, help="Disable entry", required=False, nargs='*', metavar='<IP:Domain>')
parser.add_argument('--enentry', type=str, help="Enable entry", required=False, nargs='*', metavar='<IP:Domain>')
parser.add_argument('--aentry', type=str, help="Add entry", required=False, nargs='*', metavar='<IP:Domain>')
parser.add_argument('--verifydns', type=bool, help="Verify DNS of each entry", required=False, nargs='?', metavar='NONE')
parser.add_argument('--hprint', type=bool, help="Print hosts file without exporting", required=False, nargs='?', metavar='NONE')
parser.add_argument('--errbreak', type=bool, help="Stop processing and break on ERROR", required=False, nargs='?', metavar='NONE')
parser.add_argument('--errexit', type=bool, help="Stop processing and exit on ERROR", required=False, nargs='?', metavar='NONE')
parser.add_argument('--verbose', type=bool, help="Verbose output", required=False, nargs='?', metavar='NONE')

args = parser.parse_args()

settingsF = args.sfile or 'settings.ini'
hostsF = args.hfile or '/etc/hosts'
exportF = args.efile or '__PRINT__'
addedF = args.afile or []
disabledE= args.dsentry or []
enabledE = args.enentry or []
addedE = args.aentry or []
printData = args.hprint or  False
verboseOut = args.verbose or  False
breakOnERR = args.errbreak or False
exitOnERR = args.errexit or False
verifyDNSE = args.verifydns or False

BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
CACHE_PATH = os.path.expanduser('~' + os.sep + '.cache')
TMP_PATH = os.path.expanduser('~' + os.sep + '.tmp')

def getLocalIFNames():
    MAX_BYTES = 4096
    FILL_CHAR = b'\0'
    SIOCGIFCONF = 0x8912
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    names = array.array('B', MAX_BYTES * FILL_CHAR)
    names_address, names_length = names.buffer_info()
    mutable_byte_buffer = struct.pack('iL', MAX_BYTES, names_address)
    mutated_byte_buffer = fcntl.ioctl(sock.fileno(), SIOCGIFCONF, mutable_byte_buffer)
    max_bytes_out, names_address_out = struct.unpack('iL', mutated_byte_buffer)
    namestr = names.tobytes()
    namestr[:max_bytes_out]
    bytes_out = namestr[:max_bytes_out]
    ifnamedict = []
    for i in range(0, max_bytes_out, 40):
        name = namestr[ i: i+16 ].split(FILL_CHAR, 1)[0]
        ifnamedict.append(name.decode('utf-8'))

    return ifnamedict

class HostsParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.entries = {}
        self.whitelist = []
        self.blocklist = []
        self.settings = {}
        self._load_settings()
        self.whois_server = self.settings.get('WHOIS', 'server')
        self.whois_cooldown = self.settings.getfloat('WHOIS', 'cooldown', fallback=0.5)
        self.cooldown = self.settings.getfloat('General', 'cooldown', fallback=0.5)
        self.saveF = self.settings.getboolean('General', 'save', fallback=False)
    
    def _load_settings(self):
        """Load configuration from settings.ini."""
        config = configparser.ConfigParser()
        config_path = os.path.join(BASEDIR_PATH, settingsF)
        if os.path.exists(config_path):
            config.read(config_path)
            self.settings = config
        else:
            raise Exception(f"Settings file not found: {config_path}")

    def parse(self):
        """Parse the local hosts file and store entries."""
        self._parse_blocklist()
        self._parse_allowlist()
        try:
            with open(self.file_path, 'r') as file:
                for line in file:
                    stripped_line = line.strip()
                    if not stripped_line:
                        continue
                    if stripped_line.startswith('#'):
                        if not re.match(r"#\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.-]+)", line):
                            continue
                        self._parse_disabled_line(stripped_line)
                    else:
                        self._parse_active_line(stripped_line)
        except (FileNotFoundError, PermissionError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {file_path} : {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return

    def search_domain(self, domain):
        """Search for a domain in the entries."""
        found_entries = {}
        for ip, entry in self.entries.items():
            if domain in entry['active'] or domain in entry['disabled']:
                found_entries[ip] = entry
        return found_entries

    def delete_entry(self, domain):
        """Delete a domain entry from the hosts file."""
        for ip, entry in self.entries.items():
            if domain in entry['active']:
                entry['active'].remove(domain)
            if domain in entry['disabled']:
                entry['disabled'].remove(domain)

    def move_between_blocksets(self, domain, from_blockset, to_blockset):
        """Move an entry between blocksets, e.g., from allowlist to blocklist."""
        if from_blockset == 'allowlist' and domain in self.whitelist:
            self.whitelist.remove(domain)
        elif from_blockset == 'blocklist' and domain in self.blocklist:
            self.blocklist.remove(domain)
        else:
            sys.stderr.write(f"invalid Blockset {from_blockset}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return
 
        if to_blockset == 'allowlist':
            self.whitelist.append(domain)
        elif to_blockset == 'blocklist':
            self.blocklist.append(domain)
        else:
            sys.stderr.write(f"invalid Blockset {from_blockset}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return

    def _parse_blocklist(self):
        """Parse the blocklist file."""
        blocklist_path = os.path.join(BASEDIR_PATH, '.blocklist')
        if os.path.exists(blocklist_path):
            try:
                with open(blocklist_path, 'r') as file:
                    self.blocklist = [line.strip() for line in file if line.strip()]
            except (FileNotFoundError, PermissionError, IOError) as e:
                sys.stderr.write(f"Failed to handle file {file_path} : {e}")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return

    def _parse_allowlist(self):
        """Parse the allowlist file."""
        allowlist_path = os.path.join(BASEDIR_PATH, '.allowlist')
        if os.path.exists(allowlist_path):
            try:
                with open(allowlist_path, 'r') as file:
                    self.whitelist = [line.strip() for line in file if line.strip()]
            except (FileNotFoundError, PermissionError, IOError) as e:
                sys.stderr.write(f"Failed to handle file {file_path} : {e}")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return

    def _parse_disabled_line(self, line):
        """Parse and store disabled domains."""
        line_content = line.lstrip('#').strip()
        if line_content:
            self._add_entry(line_content, active=False)

    def _parse_active_line(self, line):
        """Parse and store active domains."""
        self._add_entry(line, active=True)

    def _add_entry(self, line, active=True):
        parts = line.split()
        if len(parts) < 2:
            return

        ip_address = parts[0]
        domains = parts[1:]
        
        for domain in domains:
            if not self._validate_syntax(ip_address, domain):
                sys.stderr.write(f"Syntax validation failed for {domain} and IP {ip_address}\n")
                if exitOnERR:
                    sys.exit()
                #if breakOnERR:
                #    return
                return
            if not self._validate_domain_ip(ip_address, domain) and verifyDNSE:
                sys.stderr.write(f"DNS validation failed for {domain} and IP {ip_address}\n")
                if exitOnERR:
                    sys.exit()
                #if breakOnERR:
                #    return
                return
            
        if ip_address not in self.entries:
            self.entries[ip_address] = {'active': [], 'disabled': []}

        # Ensure no duplicates
        if active:
            for domain in domains:
                if domain not in self.entries[ip_address]['active']:
                    self.entries[ip_address]['active'].append(domain)
        else:
            for domain in domains:
                if domain not in self.entries[ip_address]['disabled']:
                    self.entries[ip_address]['disabled'].append(domain)

    def _EntryExists(self, ip_address, domain):
        if ip_address not in self.entries or (domain not in self.entries[ip_address]['active'] and domain not in self.entries[ip_address]['disabled']):
            return False
        return True 

    def insert_or_update_domain(self, ip_address, domain, active=True):
        """Insert or update a domain under a specific IP."""
        if not self._validate_syntax(ip_address, domain):
            sys.stderr.write(f"Syntax validation failed for {domain} and IP {ip_address}\n")
            if exitOnERR:
                sys.exit()
            #if breakOnERR:
            #    return
            return
        if not self._validate_domain_ip(ip_address, domain) and verifyDNSE:
            sys.stderr.write(f"DNS validation failed for {domain} and IP {ip_address}\n")
            if exitOnERR:
                sys.exit()
            #if breakOnERR:
            #    return
            return
        if ip_address not in self.entries:
            self.entries[ip_address] = {'active': [], 'disabled': []}

        if domain in self.entries[ip_address]['active']:
            self.entries[ip_address]['active'].remove(domain)
        if domain in self.entries[ip_address]['disabled']:
            self.entries[ip_address]['disabled'].remove(domain)

        if active:
            self.entries[ip_address]['active'].append(domain)
        else:
            self.entries[ip_address]['disabled'].append(domain)

    def _validate_syntax(self, ip_address, domain):
        """Validate the syntax of IP address and domain before DNS validation."""
        if not self._validate_ip(ip_address):
            sys.stderr.write(f"Invalid IP format: {ip_address}\n")
            return False
        if not self._validate_domain_syntax(domain) and domain != 'localhost':
            sys.stderr.write(f"Invalid domain format: {domain}\n")
            return False
        return True

    def _validate_domain_syntax(self, domain):
        """Check if a domain name follows a valid pattern."""
        if domain in ("localhost", "local") or domain == platform.node():
            return True
        #return validators.domain(domain)
        domain_pattern = re.compile(r"^([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z0-9-]{2,}(\.)?$")
        return bool(domain_pattern.match(domain))

    def _validate_domain_ip(self, ip_address, domain):
        """Check if the domain resolves to the given IP address using DNS."""
        try:
            __LOCAL = False
            for __IFNAME in getLocalIFNames():
                __LOCALIP = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', __IFNAME.encode('utf-8')))[20:24])
                __NETMASK = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', __IFNAME.encode('utf-8')))[20:24])
                if ip_address in ("127.0.0.1", "0.0.0.0") or domain in ("localhost", "local") or domain == platform.node() or ipaddress.ip_address(ip_address) in ipaddress.ip_network(__LOCALIP + '/' + __NETMASK, strict=False) or ip_address == socket.gethostbyname(socket.gethostname()):
                    __LOCAL = True
                    break
            if not __LOCAL:
                resolved_ip = socket.gethostbyname(domain)
                return resolved_ip == ip_address
            else:
                return __LOCAL
        except Exception as e:
            sys.stderr.write(f"DNS Verification process failed : {e}\n")
            return False

    def _validate_ip(self, ip_address):
        """Check if the provided IP address is valid."""
        try:
            __RET = True
            if not validators.ipv4(ip_address) and not validators.ipv6(ip_address):
                __RET = False
            return __RET
        except (ValueError, ValidationError):
            return False

    def save(self):
        """Save the entries back to the hosts file."""
        try:
            with open(self.file_path, 'w') as file:
                for ip_address, domain_data in self.entries.items():
                     for domain in domain_data['active']:
                         if domain in self.whitelist:
                              file.write(f"{ip_address} {domain}")
                         elif domain in self.blocklist:
                              file.write(f"0.0.0.0 {domain}")
                         else:
                             file.write(f"{ip_address} {domain}")
                     for domain in domain_data['disabled']:
                         if domain in self.whitelist:
                              file.write(f"#{ip_address} {domain}")
                         elif domain in self.blocklist:
                              file.write(f"#0.0.0.0 {domain}")
                         else:
                             file.write(f"#{ip_address} {domain}")
        except (FileNotFoundError, PermissionError, OSError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {file_path} : {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return

    def get_active_entries(self):
        return {ip: data['active'] for ip, data in self.entries.items() if data['active']}

    def get_disabled_entries(self):
        return {ip: data['disabled'] for ip, data in self.entries.items() if data['disabled']}

    def whois_lookup(self, domains, skip_cooldown=False):
        """Perform WHOIS lookup on a list of domains, with optional cooldown."""
        for domain in domains:
            try:
                whois_info = whois.whois(domain)
                sys.stdout.write(f"WHOIS info for {domain}:")
                sys.stdout.write(whois_info)
            except Exception as e:
                sys.stderr.write(f"Error performing WHOIS lookup for {domain}: {e}\n")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return
            if not skip_cooldown:
                time.sleep(self.whois_cooldown)

    def fetch_and_merge_hosts(self, url):
        """Fetch a remote hosts file from a URL and merge with local entries."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            remote_content = response.text
            for line in remote_content.splitlines():
                stripped_line = line.strip()
                if not stripped_line:
                    continue
                if stripped_line.startswith('#'):
                    self._parse_disabled_line(stripped_line)
                else:
                    parts = stripped_line.split()
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        domains = parts[1:]
                        if self._validate_syntax(ip_address, domains[0]):
                            if verifyDNSE:
                               valid_domains = [domain for domain in domains if self._validate_domain_ip(ip_address, domain)]
                               if valid_domains:
                                  self._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                               else:
                                  sys.stderr.write(f"Skipping invalid DNS entry: {stripped_line}\n")
                            else:
                                self._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                        else:
                            sys.stderr.write(f"Skipping invalid syntax entry: {stripped_line}\n")
        except requests.RequestException as e:
            sys.stderr.write(f"Failed to fetch hosts file from URL: {e}\n")

    def export(self, output_file_path):
        """Export all entries (active and disabled) to a new hosts file."""
        try:
             with open(output_file_path, 'w') as file:
                 for ip_address, domain_data in self.entries.items():
                     for domain in domain_data['active']:
                         if domain in self.whitelist:
                              file.write(f"{ip_address} {domain}")
                         elif domain in self.blocklist:
                              file.write(f"0.0.0.0 {domain}")
                         else:
                             file.write(f"{ip_address} {domain}")
                     for domain in domain_data['disabled']:
                         if domain in self.whitelist:
                              file.write(f"#{ip_address} {domain}")
                         elif domain in self.blocklist:
                              file.write(f"#0.0.0.0 {domain}")
                         else:
                             file.write(f"#{ip_address} {domain}")
        except (FileNotFoundError, PermissionError, OSError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {file_path} : {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return
                    
    def fetchList(self):
        __HOSTS__str = []
        for ip_address, domain_data in self.entries.items():
            for domain in domain_data['active']:
                if domain in self.whitelist:
                    __HOSTS__str.append(f"{ip_address} {domain}")
                elif domain in self.blocklist:
                    __HOSTS__str.append(f"0.0.0.0 {domain}")
                else:
                    __HOSTS__str.append(f"{ip_address} {domain}")
            for domain in domain_data['disabled']:
                if domain in self.whitelist:
                    __HOSTS__str.append(f"#{ip_address} {domain}")
                elif domain in self.blocklist:
                    __HOSTS__str.append(f"#0.0.0.0 {domain}")
                else:
                    __HOSTS__str.append(f"#{ip_address} {domain}")
        return __HOSTS__str

try:
    if __name__ == "__main__":
         parser = HostsParser(hostsF)
         parser.parse()

        # Blocksets
         time.sleep(0.5)
         for root, dirnames, filenames in os.walk(BASEDIR_PATH +  os.sep + 'blocksets'):
            for filename in filenames:
                try:
                     BlocksetF = open(BASEDIR_PATH + os.sep + 'blocksets'+ os.sep + filename, 'r')
                except Exception as e:
                     sys.stderr.write(f"Sorry, something went wrong\r\n{e}")
                else:
                     for line in BlocksetF.readline():
                        stripped_line = line.strip()
                        if not stripped_line:
                            continue
                        if stripped_line.startswith('#'):
                            parser._parse_disabled_line(stripped_line)
                        else:
                            parts = stripped_line.split()
                            if len(parts) >= 2:
                                ip_address = parts[0]
                                domains = parts[1:]
                                if parser._validate_syntax(ip_address, domains[0]):
                                    if verifyDNSE:
                                       valid_domains = [domain for domain in domains if parser._validate_domain_ip(ip_address, domain)]
                                       if valid_domains:
                                          parser._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                                       else:
                                          sys.stderr.write(f"Skipping invalid DNS entry: {stripped_line}\n")
                                    else:
                                        parser._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                                else:
                                    sys.stderr.write(f"Skipping invalid syntax entry: {stripped_line}\n")
                     if not BlocksetF.closed:
                         BlocksetF.close()
         time.sleep(parser.cooldown)

         for hFile in addedF:
                if verboseOut:
                    sys.stdout.write(f"Processing File {hFile}")
                parser.fetch_and_merge_hosts(hFile)
         time.sleep(parser.cooldown)

         # Disabled entries
         for entry in disabledE:
             ip,domain = entry.split(':')
             if not parser._EntryExists(ip, domain):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} isn't a valid entry'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=False)
         time.sleep(parser.cooldown)

         # Enabled  entries
         for entry in enabledE:
             ip,domain = entry.split(':')
             if not parser._EntryExists(ip, domain):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} isn't a valid entry'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=True)
         time.sleep(parser.cooldown)

         # Additional  entries
         for entry in addedE:
             ip,domain = entry.split(':')
             if parser._EntryExists(ip, domain):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} already exists'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=True)
         time.sleep(parser.cooldown)

         if parser.saveF:
             if verboseOut:
                 sys.stdout.write("overwriting original hosts file...")
             parser.save()

         if printData:
            #sys.stdout.write('\n'.join([item + '\n' for item in parser.fetchList()]))
            sys.stdout.write('\n'.join(parser.fetchList()))
         else:
             if exportF == '__PRINT__':
                 #sys.stdout.write('\n'.join([item + '\n' for item in parser.fetchList()]))
                 sys.stdout.write('\n'.join(parser.fetchList()))
             else:
                 parser.export(exportF)
except KeyboardInterrupt:
    sys.stdout.write('Exiting...')
except Exception as e:
    sys.stderr.write(f"Sorry, something went wrong\r\n{e}\n")
