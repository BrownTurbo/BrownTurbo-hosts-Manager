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
import json
import concurrent.futures
from line_profiler import profile

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

@profile
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

class FileCache:
    @profile
    def __init__(self, cache_file, flush_threshold=10):
        """Initialize the cache."""
        self.cache_file = cache_file
        self.cache = {}
        self.flush_threshold = flush_threshold
        self.buffer = []  # Buffer to hold writes
        self.load_cache()
    @profile
    def load_cache(self):
        """Load the cache from a JSON file."""
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
                if not f.closed:
                    f.close()
        except (FileNotFoundError, json.JSONDecodeError):
            self.cache = {}  # Initialize an empty cache if the file doesn't exist or is invalid
        except (PermissionError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {self.cache_file} : {e}")
            if exitOnERR:
                sys.exit()

    @profile
    def save_cache(self):
        """Save the cache to a JSON file."""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
                
                self.buffer = []  # Clear the buffer after flushing
                if not f.closed:
                   f.close()
        except (FileNotFoundError, PermissionError, OSError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {self.cache_file} : {e}")
            if exitOnERR:
                sys.exit()

    @profile
    def get(self, key):
        """Retrieve a value from the cache."""
        return self.cache.get(key)
    @profile
    def set(self, key, value):
        """Set a value in the cache and save to file."""
        self.cache[key] = value
        self.buffer.append((key, value))

        if len(self.buffer) >= self.flush_threshold:
            self.save_cache()

class DNSCache:
    @profile
    def __init__(self, cache_file, max_cache_size=100, expiration_time=60):
        """Initialize the DNS cache."""
        self.cache_file = cache_file
        self.max_cache_size = max_cache_size
        self.expiration_time = expiration_time
        self.file_cache = FileCache(self.cache_file)
    @profile
    def lookup(self, domain, timeout = 5):
        """Perform a DNS lookup for the given domain."""
        current_time = time.time()
        
        # Check if the domain is in the cache
        cache_entry = self.file_cache.get(domain)
        if cache_entry:
            ip_address, timestamp = cache_entry
            # Check if the cached entry has expired
            if current_time - timestamp < self.expiration_time:
                print(f"Cache hit for {domain}: {ip_address}")
                return ip_address
            else:
                # Remove expired entry
                del self.file_cache.cache[domain]

        # Perform DNS lookup since it's a cache miss or expired
        try:
            socket.setdefaulttimeout(timeout)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                ip_address = executor.submit(socket.gethostbyname, domain)
                try:
                    ip_address = ip_address.result(timeout=timeout)
                    self._cache_result(domain, ip_address)
                    return ip_address
                except concurrent.futures.TimeoutError:
                    sys.stderr.write(f"DNS lookup for {domain} timed out.\n")
                except socket.gaierror:
                    sys.stderr.write(f"DNS lookup failed for {domain}\n")
        except Exception as e:
            sys.stderr.write(f"Something went wrong when processing DNS Lookup for {domain}\n{e}\n")
        return None
    @profile
    def _cache_result(self, domain, ip_address):
        """Cache the result of a DNS lookup."""
        if len(self.file_cache.cache) >= self.max_cache_size:
            # Remove the oldest entry (FIFO)
            oldest_domain = next(iter(self.file_cache.cache))
            del self.file_cache.cache[oldest_domain]
            print(f"Cache full. Removed oldest entry: {oldest_domain}")

        self.file_cache.set(domain, (ip_address, time.time()))  # Cache the IP address with the current timestamp

class HostsParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.entries = []
        self.whitelist = []
        self.blocklist = []
        self.settings = {}
        self._load_settings()
        self.whois_server = self.settings.get('WHOIS', 'server')
        self.whois_cooldown = self.settings.getfloat('WHOIS', 'cooldown', fallback=0.5)
        self.cooldown = self.settings.getfloat('General', 'cooldown', fallback=0.5)
        self.saveF = self.settings.getboolean('General', 'save', fallback=False)
        self.parsed_data_cache = FileCache(os.path.join(CACHE_PATH, 'parsed_hosts_cache.json'))
        self.dns_cache = DNSCache(os.path.join(CACHE_PATH, 'dns_cache.json'), 70000)
        self.ip_cache = {}
    @profile
    def _load_settings(self):
        """Load configuration from settings.ini."""
        config = configparser.ConfigParser()
        config_path = os.path.join(BASEDIR_PATH, settingsF)
        if os.path.exists(config_path):
            config.read(config_path)
            self.settings = config
        else:
            raise Exception(f"Settings file not found: {config_path}")
    @profile
    def _chunkify(self, file, chunk_size=1000):
        """Generator function to read the file in chunks."""
        chunk = []
        for i, line in enumerate(file):
            chunk.append(line)
            if (i + 1) % chunk_size == 0:
                yield chunk
                chunk = []
        if chunk:
            yield chunk
    @profile
    def _process_chunk(self, chunk):
        """Process each chunk of entries."""
        for line_number, line in enumerate(chunk, 1):
            stripped_line = line.strip()
            if len(line) == 0 or line in ['\n', '\r\n']:
                # Blank line, store as-is
                self.entries.append(('blank', None, None, line_number, line))
                continue
            if stripped_line.startswith('#'):
                if not re.match(r"#\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.-]+)", line):
                    self.entries.append(('comment', None, None, line_number, line))
                else:
                    self._parse_disabled_line(stripped_line, line_number)
            else:
                self._parse_active_line(stripped_line, line_number)
    @profile
    def parse(self, chunk_size=1000, max_workers=15):
        """Parse the local hosts file and store entries."""
        self._parse_blocklist()
        self._parse_allowlist()
        try:
            with open(self.file_path, 'r') as file:
                chunks = list(self._chunkify(file, chunk_size))
                with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                    futures = [executor.submit(self._process_chunk, chunk) for chunk in chunks]
                    for future in concurrent.futures.as_completed(futures):
                         future.result()
                if not file.closed:
                   file.close()
        except (FileNotFoundError, PermissionError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {self.file_path}: {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return
        except Exception as e:
            print(f"Error in processing file {self.file_path}: {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return
    @profile
    def search_domain(self, domain):
        """Search for a domain in the entries."""
        found_entries = {}
        for i, (eType, ip, domains, line_number, comment) in enumerate(self.entries):
            if not eType in ['active', 'disabled']:
                continue
            if domain in domains:
                found_entries[ip] = {
                    'domains': domains,
                    'status': eType,
                    'line_number': line_number,
                    'entry': i
                }
        return found_entries
    @profile
    def delete_entry(self, eID, domain):
        """Delete a domain entry from the hosts file."""
        for i, (eType, ip, domains, line_number, comment) in enumerate(self.entries):
            if not eType in ['active', 'disabled'] or not eID == i:
                continue
            if domain in domains:
                domains.remove(domain)
    @profile
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
    @profile
    def _parse_blocklist(self):
        """Parse the blocklist file."""
        blocklist_path = os.path.join(BASEDIR_PATH, '.blocklist')
        if os.path.exists(blocklist_path):
            try:
                with open(blocklist_path, 'r') as file:
                    self.blocklist = [line.strip() for line in file if line.strip()]
                    if not file.closed:
                        file.close()
            except (FileNotFoundError, PermissionError, IOError) as e:
                sys.stderr.write(f"Failed to handle file {file_path} : {e}")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return
    @profile
    def _parse_allowlist(self):
        """Parse the allowlist file."""
        allowlist_path = os.path.join(BASEDIR_PATH, '.allowlist')
        if os.path.exists(allowlist_path):
            try:
                with open(allowlist_path, 'r') as file:
                    self.whitelist = [line.strip() for line in file if line.strip()]
                    if not file.closed:
                        file.close()
            except (FileNotFoundError, PermissionError, IOError) as e:
                sys.stderr.write(f"Failed to handle file {file_path} : {e}")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return
    @profile
    def _parse_disabled_line(self, line, line_number=None):
        """Parse and store disabled domains."""
        line_content = line.lstrip('#').strip()
        if line_content:
            self._add_entry(line_content, False, line_number)
    @profile
    def _parse_active_line(self, line, line_number=None):
        """Parse and store active domains."""
        self._add_entry(line, True, line_number)
    @profile
    def _add_entry(self, line, active=True, line_number=None):
        parts = line.split()
        if len(parts) < 2:
            return

        ip_address = parts[0]
        domains = parts[1:]
        
        for domain in domains:
            if not self._validate_syntax(ip_address, domain):
                sys.stderr.write(f"Syntax validation failed for {domain} and IP {ip_address}\n")
                self.entries.append(('ignored', None, None, line_number, line))
                return
            if not self._validate_domain_ip(ip_address, domain) and verifyDNSE:
                sys.stderr.write(f"DNS validation failed for {domain} and IP {ip_address}\n")
                if exitOnERR:
                    sys.exit()
                #if breakOnERR:
                #    return
                return

        entry_type = 'active' if active else 'disabled'
        # Ensure no duplicates
        for i, (eType, ip, dms, lnum, comment) in enumerate(self.entries):
            if not eType in ['active', 'disabled'] or not ip == ip_address or not entry_type == eType:
                continue
            if active:
                self.entries[i] = (entry_type, ip_address, list(set(dms + domains)), lnum, None)
            else:
                self.entries[i] = ('disabled', ip_address, list(set(dms + domains)), lnum, None)
            break

        # If the entry does not exist, add a new one
        if line_number is None:
            line_number = len(self.entries) + 1  # Add at the end if no line number is provided
                
        self.entries.append((entry_type, ip_address, domains, line_number, None))
    @profile
    def _EntryExists(self, ip_address, domain = None, active = True, iponly = False):
        _RET = -1
        for i, (eType, ip, dms, lnum, comment) in enumerate(self.entries):
            if not eType in ['active', 'disabled'] or not ip == ip_address:
                continue
            if ip == ip_address:
                if not iponly and not domain in dms:
                    continue
                if not active == None and not eType == 'active' if active else 'disabled':
                    continue
                _RET = i
                break
        return _RET
    @profile
    def insert_or_update_domain(self, ip_address, domain, active = True, line_number = None):
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
        __EID = self._EntryExists(ip_address, domain, active)
        entry_type = 'active' if active else 'disabled'
        _entry_type = 'disabled' if active else 'active'
        
        # If the entry does not exist, add a new one
        if line_number is None:
            line_number = len(self.entries) + 1  # Add at the end if no line number is provided
        
        if __EID == -1:
            self.entries.append((entry_type, ip_address, [domain], line_number, None))
        else:
              for eType, ip, domains, lnum, comment in self.entries[__EID]:
                  domains.remove(domain)
                  _EID = self._EntryExists(ip_address, None,  active, True)
                  if _EID == -1:
                      self.entries.append((_entry_type, ip_address, [domain], line_number, None))
                  else:
                      self.entries[_EID] = (_entry_type, ip_address, list(set(domains + [domain])), self.entries[entry_id][3], None)
    @profile
    def _validate_syntax(self, ip_address, domain):
        """Validate the syntax of IP address and domain before DNS validation."""
        if not self._validate_ip(ip_address):
            sys.stderr.write(f"Invalid IP format: {ip_address}\n")
            return False
        if not self._validate_domain_syntax(domain):
            sys.stderr.write(f"Invalid domain format: {domain}\n")
            return False
        return True
    @profile
    def _validate_domain_syntax(self, domain):
        """Check if a domain name follows a valid pattern."""
        if domain in ("localhost", "local") or domain == platform.node():
            return True
        #return validators.domain(domain)
        domain_pattern = re.compile(r"^([a-zA-Z0-9-_]{1,63}\.)+[a-zA-Z0-9-]{2,}(\.)?$")
        return bool(domain_pattern.match(domain))
    @profile
    def _validate_domain_ip(self, ip_address, domain, timeout=7):
        """Check if the domain resolves to the given IP address using DNS."""
        try:
            __LOCAL = False
            socket.setdefaulttimeout(timeout)
            for __IFNAME in getLocalIFNames():
                __LOCALIP = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', __IFNAME.encode('utf-8')))[20:24])
                __NETMASK = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 35099, struct.pack('256s', __IFNAME.encode('utf-8')))[20:24])
                if ip_address in ("127.0.0.1", "0.0.0.0") or domain in ("localhost", "local") or domain == platform.node() or ipaddress.ip_address(ip_address) in ipaddress.ip_network(__LOCALIP + '/' + __NETMASK, strict=False) or ip_address == socket.gethostbyname(socket.gethostname()):
                    __LOCAL = True
                    break
            if not __LOCAL:
                resolved_ip = self.dns_cache.lookup(domain, timeout)
                return resolved_ip == ip_address
            else:
                return __LOCAL
        except Exception as e:
            sys.stderr.write(f"DNS Verification process failed : {e}\n")
            return False
    @profile
    def _validate_ip(self, ip_address):
        """Check if the provided IP address is valid."""
        try:
            if ip_address in self.ip_cache:
                return self.ip_cache[ip_address]

            ip_obj = validators.ipv4(ip_address) or validators.ipv6(ip_address)
            self.ip_cache[ip_address] = ip_obj  # Cache the result
            return ip_obj
        except (ValueError, ValidationError):
            return False
    @profile
    def export(self, output_file_path):
        """Export all entries (active and disabled) to a new hosts file."""
        try:
             with open(output_file_path, 'w') as file:
                for i, (eType, ip, dms, lnum, comment) in enumerate(self.entries):
                     if eType == 'active':
                         for domain in dms:
                              if domain in self.whitelist:
                                 file.write(f"{ip_address} {domain}")
                              elif domain in self.blocklist:
                                 file.write(f"0.0.0.0 {domain}")
                              else:
                                 file.write(f"{ip_address} {domain}")
                     elif eType == 'disabled':
                         for domain in dms:
                              if domain in self.whitelist:
                                 file.write(f"#{ip_address} {domain}")
                              elif domain in self.blocklist:
                                 file.write(f"#0.0.0.0 {domain}")
                              else:
                                 file.write(f"#{ip_address} {domain}")
                     elif eType == 'comment':
                         file.write(f"{comment}\n")
                     elif eType == 'blank':
                         file.write("\n")
                     elif eType == 'ignored':
                         file.write("# <ignored line>\n")
                if not file.closed:
                     file.close()
        except (FileNotFoundError, PermissionError, OSError, IOError) as e:
            sys.stderr.write(f"Failed to handle file {file_path} : {e}")
            if exitOnERR:
                sys.exit()
            if breakOnERR:
                return
    @profile
    def save(self):
        """Save the entries back to the hosts file."""
        self.export(self.file_path)
    @profile
    def get_active_entries(self):
        """Return a dictionary of active IPs and their associated domains."""
        return {ip: domains for i, (eType, ip, domains, line_number, comment) in enumerate(self.entries) if eType == 'active'}
    @profile
    def get_disabled_entries(self):
        """Return a dictionary of disabled IPs and their associated domains."""
        return {ip: domains for i, (eType, ip, domains, line_number, comment) in enumerate(self.entries) if eType == 'disabled'}
    @profile
    def whois_lookup(self, domains, skip_cooldown=False):
        """Perform WHOIS lookup on a list of domains, with optional cooldown."""
        for domain in domains:
            try:
                whois_info = whois.whois(domain)
                print(f"WHOIS info for {domain}:")
                print(whois_info)
            except Exception as e:
                sys.stderr.write(f"Error performing WHOIS lookup for {domain}: {e}\n")
                if exitOnERR:
                    sys.exit()
                if breakOnERR:
                    return
            if not skip_cooldown:
                time.sleep(self.whois_cooldown)
    @profile
    def fetch_and_merge_hosts(self, url):
        """Fetch a remote hosts file from a URL and merge with local entries."""
        try:
            response = requests.get(url)
            response.raise_for_status()
            remote_content = response.text
            for line_number, line in enumerate(remote_content.splitlines(), 1):
                stripped_line = line.strip()
                if len(line) == 0 or line in ['\n', '\r\n']:
                    # Blank line, store as-is
                    self.entries.append(('blank', None, None, line_number, line))
                    continue
                if stripped_line.startswith('#'):
                    if not re.match(r"#\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.-]+)", line):
                        self.entries.append(('comment', None, None, line_number, line))
                    else:	
                        self._parse_disabled_line(stripped_line, line_number)
                else:
                    parts = stripped_line.split()
                    if len(parts) >= 2:
                        ip_address = parts[0]
                        domains = parts[1:]
                        if self._validate_syntax(ip_address, domains[0]):
                            self._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                        else:
                            sys.stderr.write(f"Skipping invalid syntax entry: {stripped_line}\n")
        except requests.RequestException as e:
            sys.stderr.write(f"Failed to fetch hosts file from URL: {e}\n")
    @profile
    def fetchData(self):
        __HOSTS__str = []
        for i, (eType, ip_address, dms, lnum, comment) in enumerate(self.entries):
             if eType == 'active':
                for domain in dms:
                    if domain in self.whitelist:
                        __HOSTS__str.append(f"{ip_address} {domain}")
                    elif domain in self.blocklist:
                        __HOSTS__str.append(f"0.0.0.0 {domain}")
                    else:
                        __HOSTS__str.append(f"{ip_address} {domain}")
             elif eType == 'disabled':
                for domain in dms:
                    if domain in self.whitelist:
                         __HOSTS__str.append(f"#{ip_address} {domain}")
                    elif domain in self.blocklist:
                        __HOSTS__str.append(f"#0.0.0.0 {domain}")
                    else:
                        __HOSTS__str.append(f"#{ip_address} {domain}")
             elif eType == 'comment':
                 __HOSTS__str.append(f"{comment}\n")
             elif eType == 'blank':
                 __HOSTS__str.append("\n")
             elif eType == 'ignored':
                 __HOSTS__str.append("# <ignored line>\n")
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
                     for line_number, line in enumerate(BlocksetF.readline(), 1):
                        stripped_line = line.strip()
                        if len(line) == 0 or line in ['\n', '\r\n']:
                            parser.entries.append(('blank', None, None, line_number, line))
                            continue
                        if stripped_line.startswith('#'):
                            if not re.match(r"#\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([\w.-]+)", line):
                                parser.entries.append(('comment', None, None, line_number, line))
                            else:
                                parser._parse_disabled_line(stripped_line, line_number)
                        else:
                            parts = stripped_line.split()
                            if len(parts) >= 2:
                                ip_address = parts[0]
                                domains = parts[1:]
                                if parser._validate_syntax(ip_address, domains[0]):
                                    parser._add_entry(f"{ip_address} {' '.join(valid_domains)}", active=True)
                                else:
                                    sys.stderr.write(f"Skipping invalid syntax entry: {stripped_line}\n")
                     if not BlocksetF.closed:
                         BlocksetF.close()
         time.sleep(parser.cooldown)

         for hFile in addedF:
                if verboseOut:
                    print(f"Processing File {hFile}")
                parser.fetch_and_merge_hosts(hFile)
         time.sleep(parser.cooldown)

         # Disabled entries
         for entry in disabledE:
             ip,domain = entry.split(':')
             if not parser._EntryExists(ip, domain, True):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} isn't a valid entry'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=False)
         time.sleep(parser.cooldown)

         # Enabled  entries
         for entry in enabledE:
             ip,domain = entry.split(':')
             if not parser._EntryExists(ip, domain, False):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} isn't a valid entry'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=True)
         time.sleep(parser.cooldown)

         # Additional  entries
         for entry in addedE:
             ip,domain = entry.split(':')
             if parser._EntryExists(ip, domain, None):
                 sys.stderr.write(f"Domain {domain} or IP Address {ip} already exists'")
                 continue
             parser.insert_or_update_domain(ip, domain, active=True)
         time.sleep(parser.cooldown)

         if parser.saveF:
             if verboseOut:
                 print("overwriting original hosts file...")
             parser.save()

         if printData:
            #print('\n'.join([item + '\n' for item in parser.fetchData()]))
            print('\n'.join(parser.fetchData()))
         else:
             if exportF == '__PRINT__':
                 #print('\n'.join([item + '\n' for item in parser.fetchData()]))
                 print('\n'.join(parser.fetchData()))
             else:
                 parser.export(exportF)
except KeyboardInterrupt:
    print('Exiting...')
except Exception as e:
    sys.stderr.write(f"Sorry, something went wrong\r\n{e}\n")
