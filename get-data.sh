#!/usr/local/bin/bash

wget --no-check-certificate https://wlcg-cric.cern.ch/api/core/rcsite/query/?json -O cric.json
ssh routemon1 vtysh -c '"show bgp ipv4 vpn community 64805:12 json"' > lhcone.ipv4.sites.json
ssh routemon1 vtysh -c '"show bgp ipv4 vpn community 64805:13 json"' > lhcone.ipv4.nren.json
ssh routemon1 vtysh -c '"show bgp ipv6 vpn community 64805:12 json"' > lhcone.ipv6.sites.json
ssh routemon1 vtysh -c '"show bgp ipv6 vpn community 64805:13 json"' > lhcone.ipv6.nren.json
