import copy
import json

from collections import Counter

import radix


roas = json.load(open("vrps.json"))["roas"]

# Compile a dictionary of ASN -> AS names
asn_to_name = {}
with open("astoname.txt", encoding="utf-8") as f:
    for line in f:
        (asn, name) = line.split(" ", 1)
        asn_to_name[asn] = name.strip()

matches = []
rtree = radix.Radix()

for idx, roa in enumerate(roas):
    rnode = rtree.add(roa["prefix"])
    rnode.data["roa"] = roa

for roa in roas:
    print(roa["prefix"])

    rnodes = rtree.search_covered(roa["prefix"])
    
    different_asns = False
    for rnode in rnodes:
        if rnode.data["roa"]["asn"] != roa["asn"]:
            different_asns = True
            match = copy.deepcopy(rnode.data["roa"])
            match["parent"] = roa
            matches.append(match)
    if different_asns:
        # matches.append(roa)
        pass

# Create dictionary of prefix -> set(asn) in order to filter those out
# We presume a DDoS protection provider normally does not announce the prefix without an ongoing attack
ris = {}
for ip in ["IPv4", "IPv6"]:
    with open(f"riswhoisdump.{ip}") as f:
        for line in f:
            if line.startswith("%") or line.strip() == "":
                continue
            (asn, prefix, _) = line.split("\t")
            if not prefix in ris:
                ris[prefix] = set()
            ris[prefix].add(f"AS{asn}")

for idx, match in enumerate(matches):
    matches[idx]["asName"] = asn_to_name.get(match["asn"], "unknown")
    matches[idx]["parent"]["asName"] = asn_to_name.get(match["parent"]["asn"], "unknown")
    try:
        del matches[idx]["source"]
    except KeyError:
        pass
    try:
        del matches[idx]["parent"]["source"]
    except KeyError:
        pass

# Filter ROAs based on whether they are:
# 1. not announced
# 2. not AS0
# 3. don't have the same name
filtered = []
for entry in matches:
    print(entry["prefix"])
    if entry["prefix"] in ris and entry["asn"] in ris[entry["prefix"]]:
        continue
    if entry["asn"] == "AS0":
        continue
    if entry["asName"] != "unknown" and entry["asName"] == entry["parent"]["asName"]:
        continue
    filtered.append(entry)

json.dump(filtered, open("filtered.json", "w"), indent=2)

# This is a complex way to count the unique number of different ASes one AS covers
# The idea being that a DDoS protection provider will have many different customers
filtered = list(set([(x["asn"], x["asName"], x["parent"]["asn"]) for x in filtered]))
unique_asns = [x[0]+ "-" + x[1] for x in filtered]
most_common = Counter(unique_asns)

json.dump(most_common.most_common(), open("most_common.json", "w"), indent=2)
