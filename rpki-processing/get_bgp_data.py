import argparse
import datetime
import gzip
import ipaddress
import os
import pickle
import pybgpstream
import time

from peer_tracker import PeerTracker

collector_list=['route-views2', 'route-views3', 'route-views4', 'route-views6','rrc00', 'rrc01','rrc03','rrc04','rrc05','rrc06'] # TODO: Update

# collector_list=['route-views2', 'route-views3', 'route-views4', 'route-views6', 'route-views.eqix', 'route-views.isc', 'route-views.kixp', 'route-views.jinx', 'route-views.linx', 'route-views.telxatl', 'route-views.wide', 'route-views.sydney', 'route-views.saopaulo', 'route-views.nwax', 'route-views.perth', 'route-views.sg', 'route-views.sfmix', 'route-views.soxrs', 'route-views.chicago', 'route-views.napafrica', 'route-views.flix', 'route-views.chile', 'route-views.amsix', 'route-views.bdix', 'route-views.bknix', 'route-views.fortaleza', 'route-views.gixa', 'route-views.gorex', 'route-views.ny', 'route-views.peru', 'route-views.phoix', 'route-views.rio', 'route-views.uaeix', 'route-views5', 'route-views2.saopaulo', 'route-views.siex', 'route-views.mwix', 'rrc00', 'rrc01','rrc02','rrc03','rrc04','rrc05','rrc06','rrc07','rrc08','rrc09','rrc10','rrc11','rrc12','rrc13','rrc14', 'rrc15','rrc16','rrc18','rrc19','rrc20','rrc21', 'rrc22', 'rrc23', 'rrc24', 'rrc25', 'rrc26']
# new_collectors = ['route-views.bdix', 'route-views.bknix', 'route-views.fortaleza', 'route-views.gixa', 'route-views.gorex', 'route-views.ny', 'route-views.peru', 'route-views.phoix', 'route-views.rio', 'route-views.uaeix', 'route-views5', 'route-views2.saopaulo', 'route-views.siex', 'route-views.mwix']
# ripe_collectors = ['rrc00', 'rrc01','rrc03','rrc04','rrc05','rrc06','rrc07','rrc08','rrc09','rrc10','rrc11','rrc12','rrc13','rrc14', 'rrc15','rrc16','rrc18','rrc19','rrc20','rrc21', 'rrc22', 'rrc23', 'rrc24']

# Bogon prefixes.
BOGON_PREFIXES_PATH = "iana-bogons.txt"
with open(BOGON_PREFIXES_PATH, 'r') as bogon_file:
    bogon_prefixes = [ipaddress.ip_network(line.strip()) for line in bogon_file.readlines()]

# Bitset configs using peer tracker.
MAX_DIRECT_PEERS = 3000
tracker = PeerTracker(max_peers=MAX_DIRECT_PEERS)

def get_bgpstream(collector_names, start_timestamp, end_timestamp, record_type='ribs'):
    """Returns the started BGPStream and the BGPRecord of recordType('rib' or 'update') created filtering by collector_name and TS (timestamp) interval"""
    stream = pybgpstream.BGPStream(
        from_time=start_timestamp,
        until_time=end_timestamp,
		collectors=collector_names,
		record_type=record_type,
        )
    return stream

def is_valid_prefix(prefix):
    # Cleaning bogon prefixes or prefixes with invalid length.
    if not prefix:
        return False

    pfx_obj = ipaddress.ip_network(prefix, strict=False)
    if pfx_obj in bogon_prefixes:
        return False

    # Check for long prefixes (/25-/32 for IPv4, /64-/128 for IPv6)
    if (pfx_obj.version == 4):
        #IPv4 prefix
        if 8 <= pfx_obj.prefixlen <= 24:
            return True
    elif (pfx_obj.version == 6):
        #IPv6 prefix
        if 8 <= pfx_obj.prefixlen <= 64:
            return True
    else:
        return False
    return False

def process_record_element(elem):
    collector_name = elem.collector
    # peer_ip = elem.peer_address
    peer_asn = elem.peer_asn
    # timestamp = str(elem.time)
    prefix = ""

    if elem.type in "RAW": #Rib Announcement Withdrawal
        prefix = elem.fields["prefix"]
        if elem.type in "RA":
            # Get the list of ASes in the AS path
            as_path = elem.fields['as-path']
            next_hop = elem.fields['next-hop']
            communities = ' '.join(elem.fields['communities'])

    if not is_valid_prefix(prefix):
        # TODO: remove print
        # print("Found bogon/invalid prefix %s" % prefix)
        return

    as_path_list = as_path.split(' ')
    if len(as_path_list) > 0:
        direct_peer = peer_asn
        direct_peer_key = str(direct_peer) + ':' + collector_name
        origin = as_path_list[-1]
        prefix_origin_key = prefix + '|' + str(origin)
        tracker.add_peer(prefix_origin_key, direct_peer_key)

    return

def get_and_process_records_for_collector(collector_name, rib_timestamp, record_type = "ribs"):
    stream = get_bgpstream(collector_names=[collector_name],
                           start_timestamp=rib_timestamp-100,
                           end_timestamp=rib_timestamp+100,
                           record_type=record_type)
    # TODO: Check if 100 is the right offset?

    elem_ctr = 0
    for elem in stream:
        process_record_element(elem)
        elem_ctr += 1

        if(elem_ctr %1000000 == 0):
            print(f"record: {elem_ctr}")

    return elem_ctr

def main():
    # Argument parser setup
    parser = argparse.ArgumentParser(description='Save BGP data from specified date and time.')
    parser.add_argument('--file_path', type=str, required=True, help='Base path for saving data')
    parser.add_argument('--date', type=str, default='20230601', help='Date in YYYYMMDD format')
    parser.add_argument('--rib_time', type=str, default='1200', help='RIB time in HHMM format')
    args = parser.parse_args()

    prgm_start_time = time.time()
    # Use provided arguments
    base_file_path = args.file_path
    date = args.date
    rib_time = args.rib_time

    dir_path = os.path.join(base_file_path, "data", "BGPStream", date)
    os.makedirs(dir_path, exist_ok=True)

    rib_date = f"{date} {rib_time}"
    rib_timestamp = int(time.mktime(datetime.datetime.strptime(rib_date, '%Y%m%d %H%M%S').timetuple()))

    total_records = 0
    for collector in collector_list:
        print(f"Getting records for collector: {collector}")
        num_of_records = get_and_process_records_for_collector(collector, rib_timestamp)
        total_records += num_of_records

    print(f"Total records from all collectors: {total_records}")

    # Get the key values from tracker.
    output_list = []
    for po in tracker.get_keys():
        dps = [dp_col.split(':')[0] for dp_col in tracker.get_peers(po)]
        pfx, origin = po.split('|')
        try:
            origin_num = int(origin)
        except:
            print(f"ERROR: Invalid PO: {po}")
            # TODO: Investigate these?
            # Example: ERROR: Invalid PO: 2402:8100::/32|{36040,38266,45271,65010,65212,65225}
            continue
        output_list.append((pfx, origin_num, set(dps)))
        # print(po+'|'+str(len(dps))+'|'+','.join(set(dps))+'\n')

    # Save the output data to a pickle file
    file_path = os.path.join(dir_path, "prefix_origin_dps.pkl.gz")
    with gzip.open(file_path, 'wb') as f:
        pickle.dump(output_list, f)

    prgm_end_time = time.time()
    print(f"Program ran for {prgm_end_time - prgm_start_time} seconds")

if __name__=='__main__':
    main()