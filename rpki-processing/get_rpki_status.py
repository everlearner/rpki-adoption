import argparse
import csv
from collections import defaultdict
import gzip
import json
import lzma
import os
import time
import pickle
import pytricia
import requests

RPKI_STATUS_MAP = {
    'v4': {
        'VALID': "v4_valid",
        'INVALID_LEN': "v4_invalidLength",
        'INVALID_ASN': "v4_invalidASN",
        'UNKNOWN': "v4_unknown"
    },
    'v6': {
        'VALID': "v6_valid",
        'INVALID_LEN': "v6_invalidLength",
        'INVALID_ASN': "v6_invalidASN",
        'UNKNOWN': "v6_unknown"
    }
}

# Get RPKI Hist Data from RIPE and store the JSON.
pyt_v4 = pytricia.PyTricia()
pyt_v6 = pytricia.PyTricia(128)

def get_rpki_data(date):
    print("Getting RPKI ROA data...")
    trust_anchors = ['arin', 'apnic', 'apnic-iana', 'apnic-ripe', 'apnic-arin', 'apnic-lacnic', 'apnic-afrinic', 'lacnic', 'afrinic', 'ripencc']
    year, month, day = date[:4], date[4:6], date[6:]
    for ta in trust_anchors:
        url = f"https://ftp.ripe.net/rpki/{ta}.tal/{year}/{month}/{day}/output.json.xz"
        # TODO: Do we need to handle older dates, which do not have json outputs?
        compressed_data = download_file(url)
        if not compressed_data:
            continue

        roas_dict = get_decompressed_dict(compressed_data)
        roas_list = roas_dict["roas"]
        v4_roas = []
        v6_roas = []

        for roa in roas_list:
            if ':' in roa["prefix"]:
                v6_roas.append(roa)
            else:
                v4_roas.append(roa)
        print(f"ROAs stats, Total = {len(roas_list)}, v4 = {len(v4_roas)}, v6 = {len(v6_roas)}")


        # Build IPv4 PyTricia tree
        for roa in v4_roas:
            prefix_str = str(roa['prefix'])
            if pyt_v4.get(prefix_str) is None:
                pyt_v4[prefix_str] = [roa]
            else:
                pyt_v4[prefix_str].append(roa)

        # Build IPv6 PyTricia tree
        for roa in v6_roas:
            prefix_str = str(roa['prefix'])
            if pyt_v6.get(prefix_str) is None:
                pyt_v6[prefix_str] = [roa]
            else:
                pyt_v6[prefix_str].append(roa)

    print("Fetched RPKI data...")
    print(f"Pytricia tree length: v4 = {len(pyt_v4)}, v6 = {len(pyt_v6)}")

def get_candidate_roas(pyt, pfx):
	'''Returns a list of jsonroas obtained from the pyt tree'''
	candidate_roas = []
	candidate_roas.extend(pyt[pfx])
	search_pfx = pyt.get_key(pfx)
	while(pyt.parent(search_pfx) is not None):
		candidate_roas.extend(pyt[pyt.parent(search_pfx)])
		search_pfx = pyt.parent(search_pfx)
	return candidate_roas

def download_file(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return response.content
    except requests.HTTPError as e:
        if e.response.status_code == 404:
            print(f"WARNING: File not found at {url} (404)")
        else:
            print(f"ERROR: Failed to download {url}: {e}")
        return None
    except requests.RequestException as e:
        print(f"ERROR: A request exception occurred for {url}: {e}")
        return None

def get_decompressed_dict(compressed_data):
    decompressor = lzma.LZMADecompressor()
    decompressed_data = decompressor.decompress(compressed_data)
    data_dict = json.loads(decompressed_data)
    return data_dict

def get_rpki_status_for_po(prefix, origin):
    # IPv4 pfx
    status = None
    if ':' not in prefix:
        # IPv4 case
        pyt = pyt_v4
        ip_version = "v4"
    else:
        # IPv6 case
        pyt = pyt_v6
        ip_version = "v6"

    pfx_len = int(prefix.split('/')[1])

    if pyt.get(prefix):
        candidate_roas = get_candidate_roas(pyt, prefix)
        candidate_origins = [int(roa['asn'].split('AS')[1]) for roa in candidate_roas]
        # tas = set([roa['ta'] for roa in candidate_roas])
        if origin in candidate_origins:
            # ASN match
            invalid_len = True
            for roa in candidate_roas:
                # print ('AS'+str(origin)+', '+str(roa['asn']))
                if 'AS'+str(origin) == str(roa['asn']):
                    #selecting ROA with matching ASN
                    # print (' AS MATCH')
                    if pfx_len <= int(roa['maxLength']):
                        # Pfx, ASN and max len match ---> RPKI valid
                        status = RPKI_STATUS_MAP[ip_version]["VALID"]
                        invalid_len = False

            if invalid_len :
                # No maxLen match --> RPKI invalid
                status = RPKI_STATUS_MAP[ip_version]["INVALID_LEN"]
        else:
            # NO ASN match --> RPKI invalid ASN
            status = RPKI_STATUS_MAP[ip_version]["INVALID_ASN"]
    else:
        #pfx not in pyt --> RPKI unknown
        status = RPKI_STATUS_MAP[ip_version]["UNKNOWN"]

    return status

def assign_rpki_status(all_prefix_origin_list):
    # Bucket the PO to correct RPKI status based on ROAs data.
    print("Assigining RPKI status...")
    dp_viu_map = defaultdict(lambda: defaultdict(set)) # TODO: Full form of this?
    data_rows = []
    elem_ctr = 0
    for prefix, origin, dp_set in all_prefix_origin_list:
        rpki_status = get_rpki_status_for_po(prefix, origin)
        for dp in dp_set:
            po_key = '|'.join([prefix, str(origin)])
            dp_viu_map[dp][rpki_status].add(po_key)

        elem_ctr += 1
        if(elem_ctr %1000000 == 0):
            print(f"Processed {elem_ctr} records.")

    print(f"Assigned RPKI status to {elem_ctr} records...")

    for dp, value in dp_viu_map.items():
        v4_valid_count = len(value[RPKI_STATUS_MAP["v4"]["VALID"]])
        v4_invalid_len_count = len(value[RPKI_STATUS_MAP["v4"]["INVALID_LEN"]])
        v4_invalid_asn_count = len(value[RPKI_STATUS_MAP["v4"]["INVALID_ASN"]])
        v4_unknown_count = len(value[RPKI_STATUS_MAP["v4"]["UNKNOWN"]])

        v6_valid_count = len(value[RPKI_STATUS_MAP["v6"]["VALID"]])
        v6_invalid_len_count = len(value[RPKI_STATUS_MAP["v6"]["INVALID_LEN"]])
        v6_invalid_asn_count = len(value[RPKI_STATUS_MAP["v6"]["INVALID_ASN"]])
        v6_unknown_count = len(value[RPKI_STATUS_MAP["v6"]["UNKNOWN"]])
        data_rows.append((dp, v4_valid_count, v4_invalid_len_count, v4_invalid_asn_count, v4_unknown_count,
                              v6_valid_count, v6_invalid_len_count, v6_invalid_asn_count, v6_unknown_count))
    return data_rows

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description='Save BGP data from specified date and time.')
    parser.add_argument('--file_path', type=str, required=True, help='Base path for saving data')
    parser.add_argument('--date', type=str, default='20230601', help='Date in YYYYMMDD format')
    args = parser.parse_args()

    prgm_start_time = time.time()
    # Use provided arguments
    base_file_path = args.file_path
    date = args.date

    # Get RPKI data
    get_rpki_data(date)

    prefix_orgin_data_file = os.path.join(base_file_path, "data", "BGPStream", date, "prefix_origin_dps.pkl.gz")
    with gzip.open(prefix_orgin_data_file, 'rb') as f:
        # TODO: Handle file not found?
        po_list = pickle.load(f)

    rpki_status_list = assign_rpki_status(po_list)

    print("Storing the aggregated data")
    csv_file_dir = os.path.join(base_file_path, "data", "RPKI", date)
    os.makedirs(csv_file_dir, exist_ok=True)
    csv_file_path = os.path.join(csv_file_dir, "rpki_status_counts.csv")

    with open(csv_file_path, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Write the header
        writer.writerow(["direct_peer", "v4_valid", "v4_invalidLength", "v4_invalidASN", "v4_unknown",
                                        "v6_valid", "v6_invalidLength", "v6_invalidASN", "v6_unknown"])
        # Write all the rows
        writer.writerows(rpki_status_list)
        # TODO: Compress csv?

    print(f"Data stored at {csv_file_path}")

    prgm_end_time = time.time()
    print(f"Program ran for {prgm_end_time - prgm_start_time} seconds")

if __name__=='__main__':
    main()