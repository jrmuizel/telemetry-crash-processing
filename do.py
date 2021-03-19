#!/usr/local/bin/python3

# Usage:
# pip install fx-crash-sig
#
# Using https://sql.telemetry.mozilla.org/queries/78742/source
# you can get an API key url https://sql.telemetry.mozilla.org/api/queries/78742/results.json?api_key=[key]
# for a results.json. Download that and then run this script.

import json
with open('results.json') as f:
  dataset = json.load(f)
props = []
#for r in dataset["query_result"]["data"]["rows"]:
  #j = json.loads(r["additional_properties"])
  #j["payload"]["metadata"] = json.loads(r["metadata"])
  #props.append(j)
#print(props)
from fx_crash_sig.crash_processor import CrashProcessor

proc = CrashProcessor()
def symbolicate(ping):
  try:
    return proc.symbolicate(ping)
  except TypeError:
    return None

def sig_of_sym(payload):
  if payload is None:
    return ""
  try:
    return proc.get_signature_from_symbolicated(payload).signature
  except TypeError:
    return ""

from collections import Counter
sigs = Counter()
import os
import pprint
pp = pprint.PrettyPrinter(indent=4)
for r in dataset["query_result"]["data"]["rows"]:
  props = json.loads(r["payload"])
  payload = symbolicate(r)
  sig = sig_of_sym(payload)
  
  if len(sig) > 200:
      sig = sig[0:200]
  sig += " - " + str(props['metadata']['moz_crash_reason'])
  
  sigs[sig] += 1
  os.makedirs("crashes/" + sig, exist_ok=True)
  with open("crashes/" + sig + "/" + props["crash_id"], "w") as fout:
     fout.write(pprint.pformat(payload))
  #print(sig)
  pp.pprint(sigs)
