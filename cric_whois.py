import re
import sys
import time
import os

# NOTE: This script now requires the 'python-ipwhois' library for reliable lookups.
# Install it using: pip install python-ipwhois
try:
    # We now import IPWhois and necessary exception types, using HostLookupError
    # instead of the incorrect HostnameResolveError.
    from ipwhois import IPWhois
    from ipwhois.exceptions import ASNRegistryError, HostLookupError
except ImportError:
    print("Error: The 'python-ipwhois' library is not installed.")
    print("Please install it using: pip install python-ipwhois")
    sys.exit(1)
except Exception as e:
    # Catch any other setup errors related to the library
    print(f"Error initializing ipwhois: {e}")
    sys.exit(1)


# Default filename to look for if no argument is provided
DEFAULT_FILENAME = "not_in_cric.txt"

def clean_ip_address(prefix: str) -> str:
    """
    Strips the CIDR netmask (/XX) from the IPv6 prefix string, 
    returning only the IP address part.
    """
    if '/' in prefix:
        return prefix.split('/')[0]
    return prefix


def parse_and_fetch_netnames(data: str) -> list[dict]:
    """
    Parses the input data to extract IPv6 prefixes, then fetches the
    corresponding network name (ASN description or NetName) using IPWhois.
    
    Args:
        data (str): The entire content read from the input file.
        
    Returns:
        list[dict]: A list of dictionaries containing prefix, AS number, and netname.
    """
    # REGEX to capture the IPv6 prefix and the AS path string.
    #regex = r"prefix\s+(?P<prefix>[\w:/]+).*?'as-path':\s*'(?P<as_path>[\d\s]+)'"
    regex = r"prefix\s+(?P<prefix>[\w.:/]+).*?'as-path':\s*'(?P<as_path>[\d\s]+)'"
    
    # Use a set to store unique IP addresses (without netmask) to avoid redundant lookups
    unique_ips = set()
    parsed_lines = []

    # 1. First Pass: Parse and collect unique Prefixes
    for line in data.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
            
        match = re.search(regex, line)
        if match:
            # Capture the full prefix string (e.g., 2001:2f8:3e:cc23::/64)
            prefix = match.group('prefix')
            print(prefix)
            
            # Clean the prefix to get just the IP address
            ip_address = clean_ip_address(prefix)
            
            as_path_str = match.group('as_path').strip() # e.g., '20965 216467'

            # Extract the ORIGINATOR AS (the last AS in the path string) for output display
            as_list = as_path_str.split()
            if as_list:
                as_number = as_list[-1] 
            else:
                print(f"Warning: AS-Path is empty for line: {line}", file=sys.stderr)
                continue
            
            # Add the cleaned IP address to the unique set for caching lookups
            unique_ips.add(ip_address)
            
            # Store the data for the final output structure.
            parsed_lines.append({
                'prefix': prefix, # Keep the original prefix for the final table display
                'ip_address': ip_address, # Store cleaned IP for lookup/cache key
                'as_number': as_number,
                'netname': 'Pending Lookup' # Placeholder
            })
        else:
            print(f"Warning: Could not parse line: {line}", file=sys.stderr)

    # Dictionary to cache IPWhois results keyed by the cleaned IP address
    ip_cache = {}

    # 2. Second Pass: Perform RDAP/WHOIS lookup for unique IPs using IPWhois
    print(f"\nFound {len(unique_ips)} unique IP Addresses. Starting ipwhois lookups...")
    
    for ip_address in unique_ips:
        # WHOIS queries can be slow, so we cache and add a small delay to be polite
        print(f"-> Querying for IP {ip_address}...", end=' ', flush=True)
        
        try:
            # Instantiate the IPWhois object with the cleaned IP address
            obj = IPWhois(ip_address)
            
            # Perform the lookup using RDAP (preferred)
            results = obj.lookup_rdap(depth=1)
            
            # Prioritize the ASN description as the "netname"
            netname = results.get('asn_description')
            asn = results.get('asn')
            descr = results.get('network').get('remarks')
            
            if not netname and results.get('network', {}).get('name'):
                # Fallback to NetName (network name) if ASN description is missing
                netname = results['network']['name']

            if not netname:
                 netname = 'Not Found (No organization name in RDAP)'
            
            ip_cache[ip_address] = netname
            print(f"Name: {netname} {descr}")
            
        except ASNRegistryError:
            netname = 'Not Found (IP not registered in RIR)'
            ip_cache[ip_address] = netname
            print(f"Failed. Error: IP not registered.")
        except HostLookupError: # Corrected exception name
            netname = 'Lookup Failed (Cannot resolve host)'
            ip_cache[ip_address] = netname
            print(f"Failed. Error: Cannot resolve host.")
        except Exception as e:
            # Catch other potential connection or library errors
            netname = f"Lookup Failed ({type(e).__name__})"
            ip_cache[ip_address] = netname
            print(f"Failed. Error: {type(e).__name__}")
        
        # Pause for a brief moment to avoid rapid-fire requests
        time.sleep(0.5) 

    # 3. Third Pass: Update the parsed lines with the fetched NetNames
    final_results = []
    for line_data in parsed_lines:
        # Use the cleaned IP address as the key to look up the cached netname
        ip_address = line_data['ip_address']
        line_data['netname'] = ip_cache.get(ip_address, 'Error: Cache Miss')
        
        # Remove the temporary 'ip_address' key before final output
        del line_data['ip_address']
        
        final_results.append(line_data)
        
    return final_results

def main():
    """
    Main execution function. Reads data from a file specified as a command-line
    argument or defaults to 'asn_input.txt'.
    """
    # Determine the input filename
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        filename = DEFAULT_FILENAME

    # Check if the file exists
    if not os.path.exists(filename):
        print(f"Error: Input file '{filename}' not found.")
        print("Usage: python asn_resolver.py <path_to_input_file>")
        sys.exit(1)

    # Read the file content
    try:
        with open(filename, 'r') as f:
            input_data = f.read()
    except Exception as e:
        print(f"Error reading file {filename}: {e}")
        sys.exit(1)

    # Validate content
    if not input_data.strip():
        print(f"Warning: File '{filename}' is empty. Exiting.")
        sys.exit(0)

    # Process data
    results = parse_and_fetch_netnames(input_data)

    # Output results
    print("\n" + "="*50)
    print(f"Final Processed Results from {filename}")
    print("="*50)
    
    # Print the results in a clean, tabular format
    print(f"{'AS Number':<10} | {'Prefix':<25} | {'Organization/NetName'}")
    print("-" * 10 + "-+-" + "-" * 25 + "-+-" + "-" * 40)
    
    for item in results:
        print(
            f"{item['as_number']:<10} | {item['prefix']:<25} | {item['netname']}"
        )
    print("="*50)

if __name__ == "__main__":
    main()

