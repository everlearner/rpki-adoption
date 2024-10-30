# rpki-processing
RPKI data processing pipeline. It downloads data from BGPStream, extracts prefix-origin data, fetches RPKI ROA data from RIPE, and assigns the RPKI status to the records.

## Steps
### 1. Getting the BGP data
```bash
python3 get_bgp_data.py --file_path ./test-dir --date 20241010
```
It stores the data to `test-dir/data/BGPStream/date/prefix_origin_dps.pkl.gz`
### 2. Getting the RPKI data and assigning status
```bash
python3 get_rpki_status.py --file_path ./test-dir --date 20241010
```
It stores the data to `test-dir/data/RPKI/date/rpki_status_counts.csv`
