#!/usr/bin/env python3

import json
import pytricia

DEBUG = False

with open('cric.json') as cric_file:
    cric_data = json.load(cric_file)

cric = pytricia.PyTricia(128)
esnetrib = pytricia.PyTricia(128)

# this function originally provided by Edoardo Martelli at
# https://twiki.cern.ch/twiki/pub/LHCONE/LhcOneVRF/extract-lhcone-prefixes.py.txt
# process data in json file
for rcsite in cric_data:
    # if a site has any 'netroutes' record:
    if (cric_data[rcsite]['netroutes']):
        for netsite in cric_data[rcsite]['netroutes']:
            # if is connected to LHCONE
            if (cric_data[rcsite]['netroutes'][netsite]['lhcone_bandwidth_limit'] >= 0):
                for af in ['ipv4','ipv6']:
                    # prefixes, if any
                    if af in cric_data[rcsite]['netroutes'][netsite]['networks']:
                        for prefix in cric_data[rcsite]['netroutes'][netsite]['networks'][af]:
                            if DEBUG: print(f"cric prefix {prefix} asn {cric_data[rcsite]['netroutes'][netsite]['asn']}")
                            pfx_attributes = dict()
                            pfx_attributes['asn'] = cric_data[rcsite]['netroutes'][netsite]['asn']
                            pfx_attributes['netsite'] = netsite
                            pfx_attributes['rcsite'] = rcsite
                            cric[prefix] = pfx_attributes


# files dumped from FRR on routemon1 via:
# vtysh -c "show bgp ipv4 vpn community 64805:12 json" > lhcone.ipv4.sites.json
# vtysh -c "show bgp ipv4 vpn community 64805:13 json" > lhcone.ipv4.nren.json
# vtysh -c "show bgp ipv6 vpn community 64805:12 json" > lhcone.ipv6.sites.json
# vtysh -c "show bgp ipv6 vpn community 64805:13 json" > lhcone.ipv6.nren.json
rib_files = [
    'lhcone.ipv4.nren.json',
    'lhcone.ipv4.sites.json',
    'lhcone.ipv6.nren.json',
    'lhcone.ipv6.sites.json'
]

for file in rib_files:
    with open(file) as rib_file:
        rib = json.load(rib_file)
    
    for router in rib["routes"]["routeDistinguishers"]:
        for prefix in rib["routes"]["routeDistinguishers"][router]:
            for route in rib["routes"]["routeDistinguishers"][router][prefix]:
                if DEBUG: print(f"router {router} prefix {prefix} as-path {route['path']}")
                pfx_attributes = dict()
                pfx_attributes['as-path'] = route['path']
                #pfx_attributes['asn'] = route['path'].split()[-1]
                esnetrib[prefix] = pfx_attributes


for pfx in esnetrib:
    if pfx not in cric:
         print(f"prefix {pfx} {esnetrib[pfx]} not in cric")
    else:
        pass
        #print(f"found prefix {pfx} in cric")


for pfx in cric:
    if pfx not in esnetrib:
         print(f"prefix {pfx} {cric[pfx]} not in esnet rib")
    else:
        pass
        #print(f"found prefix {pfx} in cric")
    #print(pfx)

print(f"{len(esnetrib)} entries in esnet lhcone")
print(f"{len(cric)} entries in cric")
