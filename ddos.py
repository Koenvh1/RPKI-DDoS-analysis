import copy
import csv
import datetime
import json

from collections import Counter
import zlib

import radix
import requests


def gather(year, month, day):
    # Compile a dictionary of ASN -> AS names
    asn_to_name = {}
    with open("astoname.txt", encoding="utf-8") as f:
        for line in f:
            (asn, name) = line.split(" ", 1)
            asn_to_name[asn] = name.strip()

    matches = []
    rtree = radix.Radix()

    roas = []

    for rir in ["ripencc", "lacnic", "arin", "apnic", "afrinic"]:
        csv_data = requests.get(f"https://ftp.ripe.net/rpki/{rir}.tal/{year}/{month:02d}/{day:02d}/roas.csv")
        reader = csv.DictReader(csv_data.content.decode("utf-8").splitlines())
        for row in reader:
            roas.append({"asn": row["ASN"], "prefix": row["IP Prefix"]})

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
    for ip in [("", "2"), ("6", "6")]:
        for sample_time in range(24):
            ris_data = requests.get(f"https://publicdata.caida.org/datasets/routing/routeviews{ip[0]}-prefix2as/{year}/{month:02d}/routeviews-rv{ip[1]}-{year}{month:02d}{day:02d}-{sample_time:02d}00.pfx2as.gz")
            if ris_data.status_code != 404:
                break
        ris_text = zlib.decompress(ris_data.content, 16 + zlib.MAX_WBITS).decode("utf-8")
        for line in ris_text.splitlines():
            # if line.startswith("%") or line.strip() == "":
            #     continue
            (ip, prefix_length, asn) = line.split("\t")
            prefix = f"{ip}/{prefix_length}"
            if not prefix in ris:
                ris[prefix] = set()
            ris[prefix].add(f"AS{asn}")

    for idx, match in enumerate(matches):
        matches[idx]["asName"] = asn_to_name.get(match["asn"], "unknown")
        matches[idx]["parent"]["asName"] = asn_to_name.get(match["parent"]["asn"], "unknown")

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

    json.dump(filtered, open(f"results/{year}{month:02d}{day:02d}-filtered.json", "w"), indent=2)

    # This is a complex way to count the unique number of different ASes one AS covers
    # The idea being that a DDoS protection provider will have many different customers
    filtered = list(set([(x["asn"], x["asName"], x["parent"]["asn"]) for x in filtered]))
    unique_asns = [x[0]+ "-" + x[1] for x in filtered]
    most_common = Counter(unique_asns)

    json.dump(most_common.most_common(), open(f"results/{year}{month:02d}{day:02d}-most_common.json", "w"), indent=2)

if __name__ == "__main__":
    start_year = 2022
    start_month = 2
    start_day = 17
    duration_in_days = 14

    base = datetime.datetime(start_year, start_month, start_day)
    date_list = [base + datetime.timedelta(days=x) for x in range(duration_in_days)]

    for date in date_list:
        print("Gathering", date)
        gather(date.year, date.month, date.day)