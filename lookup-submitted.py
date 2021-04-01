#!/usr/bin/env python3

# Using https://sql.telemetry.mozilla.org/queries/78742/source
# you can get an API key url https://sql.telemetry.mozilla.org/api/queries/78742/results.json?api_key=[key]
# for a results.json. Download that and then run this script.
import sys
import json
import os
import pprint
import itertools
import datetime
import time

with open(sys.argv[1]) as f:
  dataset = json.load(f)

props = []

pp = pprint.PrettyPrinter(indent=4)
i = 0
minidumps = []
for r in dataset["query_result"]["data"]["rows"]:
  props = json.loads(r["payload"])
  if not props['minidump_sha256_hash']:
      continue
  
  # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 is the hash of no minidump
  if props['minidump_sha256_hash'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
      continue

  minidumps.append(props['minidump_sha256_hash'])


def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk

print("looking up hashes...")
sha256_map = {}
count = 0
for sha256s in chunked_iterable(minidumps, 32):
    import requests
    sleep_time = 0
    count += len(sha256s)
    q = "&".join(["minidump_sha256_hash=" + sha256 for sha256 in sha256s])
    end_date = datetime.date.today()
    days = datetime.timedelta(7)
    start_date = end_date - days
    
    while True:
        minidump_query = "https://crash-stats.mozilla.org/api/SuperSearch/?" + q + "&date=%3E%3D" + str(start_date) + "&date=%3C" + str(end_date) + "&_facets=signature&_columns=uuid&_columns=minidump_sha256_hash"
        response = requests.get(minidump_query)
        if response.status_code == 429:
            print("waiting: " + str(sleep_time))
            time.sleep(sleep_time)
            sleep_time += 1
            continue
        else:
            break
    hits = response.json()['hits']
    if len(hits) > 0:

        print(hits)
        print(str(count) + " of " + str(len(minidumps)))
        for h in hits:
            sha256_map[h['minidump_sha256_hash']] = h['uuid']
with open('hash-to-uuid.json', 'w') as fp:
    json.dump(sha256_map, fp)
