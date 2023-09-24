import re
import json
import time 
import requests
import pandas as pd
from itertools import chain
from user_agent import generate_user_agent

ST = time.time()

data = json.loads(open("sources.json", "r").read())

def fetch_ips(url, pattern):
	headers = {"User-Agent":generate_user_agent()}
	resp = requests.get(url, headers=headers)
	if resp.status_code == 200:
		ips = list(set(re.findall(pattern, resp.text)))
		print (f"Found {len(ips)} in {url}")
		return ips
	return []

ips = {}
for item in data:
	ips[item] = fetch_ips(data[item]["url"], data[item]["regex"])

reports = [list(data.keys())]
reports[0][:0] = ["IPs"] 
all_ips = list(set(chain.from_iterable(ips.values())))
for item in  all_ips:
	tmp = [ 1 if item in ips[src] else 0 for src in data.keys()]
	tmp[:0] = [item]
	reports.append(tmp)

df = pd.DataFrame(reports[1:],columns=reports[0])

print (f"Took {round(time.time()-ST, 3)} seconds")

df.to_csv("ips", encoding='utf-8', index=False)
with open("ips.txt", "w") as f:
	f.write('\n'.join(all_ips))

'''

{
    "sblam": {
	"url": "https://sblam.com/blacklist.txt",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "interserver": {
	"url": "https://sigs.interserver.net/ipslim.txt",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "cinsscore": {
	"url": "http://cinsscore.com/list/ci-badguys.txt",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
	},
    "danger.rulez": {
	"url": "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "3coresec": {
	"url": "https://blacklist.3coresec.net/lists/all.txt",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "octopusrbl": {
	"url": "https://octopusrbl.monster/fwrules/emerging-Block-IPs.txt",
	"regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "ipsum": {
        "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        "regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "bl.de": {
        "url": "https://lists.blocklist.de/lists/all.txt",
        "regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "talos": {
        "url": "https://www.talosintelligence.com/documents/ip-blacklist",
        "regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "binary_defence": {
        "url": "http://www.binarydefense.com/banlist.txt",
        "regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    },
    "green_snow": {
        "url": "https://blocklist.greensnow.co/greensnow.txt",
        "regex": "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    }
}
'''
