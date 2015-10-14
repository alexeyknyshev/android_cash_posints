#!/usr/bin/python3

import os, sys, sqlite3
import json
import requests

def getBanksData():
  url = "http://www.banki.ru/api/"
  headers = {
    "Connection": "keep-alive",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Origin": "http://www.banki.ru",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.130 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Referer": "http://www.banki.ru/banks/map/Moskva/",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "ru-RU,ru;q=0.8,en-US;q=0.6,en;q=0.4"
  }
  reqData = {
    "jsonrpc": "2.0",
    "method": "bankInfo/getBankList",
    "params": {},
    "id": "test"
  }
  r = requests.post(url, headers = headers, data = json.dumps(reqData))
  responseJson = r.json()
  bankList = responseJson['result']['data']

  nameIdMap = {}

  for b in bankList:
    nameIdMap[b['bank_name']] = b['bank_id']

  prepared_tuples = []
  alt_ids = {}

  for b in bankList:
    # try to detect: is it branch in some city?
    dashIndex = b['bank_name'].find(u'\u2014')
    if b['bank_name'] and not b['licence'] and dashIndex != -1:
      cleanName = b['bank_name'][:dashIndex].strip()

      if cleanName in nameIdMap:
        parentId = nameIdMap[cleanName]
        alt_ids[b['bank_id']] = parentId
      else:
        raise NameError(cleanName)

    prepared_tuples.append( (b['bank_id'], b['bank_name'], b['licence'], b['name_eng'], b['region']) )

  return (prepared_tuples, alt_ids.items())

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("input db (old) is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("output db file is not specified")
    sys.exit(2)

  inputDB = sys.argv[1]
  outputDB = sys.argv[2]

  if not os.path.isfile(inputDB):
    print('no such file: ' + inputDB)
    sys.exit(3)

  if os.path.isfile(outputDB):
    os.remove(outputDB)
    print('removed file:', outputDB)

  mapByLicence = {}

  bd = sqlite3.connect(inputDB)
  curs = bd.cursor()
  for row in curs.execute('SELECT licence, id, url, tel FROM banks'):
    licence = row[0]
    raiting = row[1]
    latname = row[2]
    tel     = row[3]

    latnameSplit = latname.split('/')
    if len(latnameSplit) > 3:
      latname = latnameSplit[3]
    else:
      latname = ""

    if not licence in mapByLicence:
      mapByLicence[licence] = (raiting, latname, tel)
    else:
      oldValue = mapByLicence[licence]
      existsRaiting = oldValue[0]
      if raiting < existsRaiting:
        mapByLicence[licence] = (raiting, oldValue[1], oldValue[2], latname)

#  for mbl in mapByLicence.items():
#    print(mbl)

  bd = sqlite3.connect(outputDB)
  curs = bd.cursor()
  curs.execute('CREATE TABLE banks (id integer primary key, name text, licence integer, name_tr text, region text, raiting integer, name_tr_alt text, tel text)')
  curs.execute('CREATE TABLE banks_mapping (id integer primary key, parent integer)')

  prepared_tuples = getBanksData()
  banksData = prepared_tuples[0]
  banksBranches = prepared_tuples[1]

  banksDataFull = []
  for bdata in banksData:
    licenceStr = bdata[2]
    if not licenceStr.isdigit():
      continue

    licence = int(licenceStr)
    if licence in mapByLicence:
      banksDataFull.append( bdata + mapByLicence[licence] )
    else:
      banksDataFull.append( bdata + (65535, "", "") )

  try:
    curs.executemany('INSERT INTO banks VALUES (?,?,?,?,?,?,?,?)', banksDataFull)
  except sqlite3.ProgrammingError:
    print(banksData)
    raise

  curs.executemany('INSERT INTO banks_mapping VALUES (?,?)', banksBranches)

  bd.commit()
  bd.close()
