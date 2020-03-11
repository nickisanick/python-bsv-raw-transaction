import json
import requests
import time
current_block = 625750
def crawl(query, height):
  global current_block
  # Create a timestamped query by applying the "$gt" (greater than) operator with the height
  query['q']['find']['blk.i'] = { "$gt" : height }
  r = requests.post('https://txo.bitbus.network/block', 
    headers = {
      'Content-Type': 'application/json; charset=utf-8',
    #   'token': '<your token from https://token.planaria.network>'
    },
    data = json.dumps(query)
  )
  # Split NDJSON stream by line
  for line in r.iter_lines():
    j = json.loads(line.decode('utf-8'))
    # Update the current_block height when a tx with new block is discovered
    if (j['blk']['i'] > current_block):
      current_block = j['blk']['i']
      print('current block:', current_block)
    # Print tx line to stdout
    print('\n', j)
def crawler():
  print('crawling from', current_block)
  crawl({
   "q":  {
      "find": { "out.s2": "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"}, 
      "sort": { "blk.i": 1 },
      "project": { "blk": 1, "tx.h": 1, "out.s4": 1, "out.o1": 1 }
  }
}, current_block)
  print('crawl again in 10 seconds')
  time.sleep(10)
#   crawler()
crawler()