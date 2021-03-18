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
i = 0
for r in dataset["query_result"]["data"]["rows"]:
  props = json.loads(r["payload"])
  props['stackTraces'] = props['stack_traces']
  #props["payload"]["metadata"] = json.loads(r["metadata"])
  payload = symbolicate(props)
  sig = sig_of_sym(payload)
  if len(sig) == 0:
    continue
  if sig == 'EMPTY: no crashing thread identified':
      pp.pprint(props)
  elif 'function' not in payload['threads'][payload['crashing_thread']]['frames'][0]:
      #breakpoint()

      payload = symbolicate(props)
      sig = payload['threads'][payload['crashing_thread']]['frames'][0]['module']
      sig = func
      func = payload['threads'][payload['crashing_thread']]['frames'][0]['normalized']
      frame = 0
      while "<T>" in func and frame < len(payload['threads'][payload['crashing_thread']]['frames']):
        func = payload['threads'][payload['crashing_thread']]['frames'][frame]['normalized']
        frame += 1
      sig += " | " + func

  if len(sig) > 200:
      sig = sig[0:200]
  sig += " - " + str(props['metadata']['moz_crash_reason'])
  
  sigs[sig] += 1
  os.makedirs("crashes/" + sig, exist_ok=True)
  with open("crashes/" + sig + "/" + props["crash_id"], "w") as fout:
     fout.write(pprint.pformat(payload))
  print(sig)
  pp.pprint(sigs)
#pp.pprint(sigs)
#print(sigs)
