#!/usr/bin/python3

import os, sys, sqlite3
import json
import requests
import math
import time
import fnmatch
import re
from html.parser import HTMLParser
from region_list_dumper import getPostResponseJsonData

noMeaningInfo = [
    "С функцией приема наличных",
    "с функцией приема наличных",
    "С функцией приёма наличных",
    "С функцией приемам наличных",
    "С функцией приема наличности",
    "С функциями приема наличных",
    "С функцией выдачи наличных",
    "С Функцией приема наличных",
    "Почтовый адрес: 188640, Ленинградская область, г.&nbsp;Всеволожск, Всеволожский пр., д.&nbsp;29",
    "Почтовый адрес: 188640, Ленинградская обл., г.&nbsp;Всеволожск, Всеволожский пр., д.&nbsp;29",
    "<br />",
    "Валюта: ",
    "Вылюта: ",
    "Ваоюта: .",
    "валюта: ",
    "рубли",
    "убли",
    "доллары",
    "США",
    "евро",
    "В данном офисе не оказываются услуги потребительского кредитования",
    "Банкомат ."
    ]

noFreeAccessPatternList = [
    "Вход по пропускам",
    "Вход по пропускам через центральный подъезд",
    "Вход по пропускам через центральный подъезд",
    "Действует пропускная система",
    "Вход по постоянным пропускам. Разовые пропуска не оформляются",
    "Доступ по пропускам",
    "Доступ ограничен и осуществляется по пропускам",
    "Доступ в отделение ограничен",
    "Ограниченный доступ в офис",
    "Пропускной режим по удостоверениям ОАО &laquo;РЖД&raquo;",
    "В режиме работы организации, ограниченный доступ",
    "Вход только по пропускам мэрии"
    ]

batchSize = 25

htmlParser = HTMLParser()

def htmlEntitiesToUnicode(text):
    return htmlParser.unescape(text)

class CashPoint:
  def __init__(self):
    self.point_id = 0
    self.point_type = ""
    self.bank_id = 0
    self.town_id = 0
    self.longitude = 0.0
    self.latitude = 0.0
    self.address = ""
    self.address_comment = ""
    self.metro_name = ""
    self.free_access = True
    self.main_office = 0
    self.without_weekend = 0
    self.round_the_clock = False
    self.works_as_shop = False
    self.schedule_general = ""
    self.schedule_private = ""
    self.schedule_vip = ""
    self.tel = ""
    self.additional = ""
    self.cash_in = False

  def fromJsonData(self, data):
    self.point_id = int(data['id'])
    self.point_type = data['type']
    self.bank_id = int(data['bank_id'])
    self.town_id = int(data['region_id'])
    self.longitude = float(data['longitude']) if data['longitude'] is not None else 0.0
    self.latitude = float(data['latitude']) if data['latitude'] is not None else 0.0
    self.address = data['address']
    self.address_comment = htmlParser.unescape(data['comment_to_address'])
    #print(self.address_comment)
    self.metro_name = data['metro_name']
    self.free_access = not bool(data['is_at_closed_place'])
    self.main_office = int(data['is_main_office'])
    self.without_weekend = int(data['without_weekend'])
    self.round_the_clock = bool(data['is_round_the_clock'])
    self.works_as_shop = bool(data['is_works_as_shop'])
    self.schedule_general = data['schedule_general']
    self.schedule_private = data['schedule_private_person']
    self.schedule_vip = data['schedule_vip']
    self.tel = data['phone']
    self.additional = data['additional']
    self.cash_id = False

  def toTuple(self):
    return (self.point_id, self.point_type, self.bank_id, self.town_id, self.longitude, self.latitude, self.address, self.address_comment, self.metro_name, self.free_access, self.main_office, self.without_weekend, self.round_the_clock, self.works_as_shop, self.schedule_general, self.schedule_private, self.schedule_vip, self.tel, self.additional)

  def toTupleNew(self):
    self.schedule_general = htmlParser.unescape(self.schedule_general)
    self.schedule_private = htmlParser.unescape(self.schedule_private)
    self.schedule_vip     = htmlParser.unescape(self.schedule_vip)

    rub = True
    usd = False
    eur = False

    hit = False
    if len(self.additional) != 0:
      add =  self.additional.lower()
      if fnmatch.fnmatch(add, "*валюта:*"):
        hit = True
        if not fnmatch.fnmatch(add, "*рубли*"):
          rub = False
        if fnmatch.fnmatch(add, "*доллары*"):
          usd = True
        if fnmatch.fnmatch(add, "*евро*"):
          eur = True

      for pattern in noMeaningInfo:
        self.additional = re.sub(pattern, "", self.additional)

      oldLen = len(self.additional)
      for pattern in noFreeAccessPatternList:
        self.additional = re.sub(pattern, "", self.additional)

      if oldLen != len(self.additional):
        self.free_access = False

      self.additional = self.additional.rstrip(",.;\n\t ")
      self.additional = self.additional.lstrip(",.;\n\t ")
      self.additional = "" if len(self.additional) < 3 else self.additional

#    if hit:
#      self.additional = ""

    return (self.point_id, self.point_type, self.bank_id, self.town_id, self.longitude, self.latitude, self.address, self.address_comment, self.metro_name, self.free_access, self.main_office, self.without_weekend, self.round_the_clock, self.works_as_shop, self.schedule_general, self.schedule_private, self.schedule_vip, self.tel, self.additional, rub, usd, eur, self.cash_in)

  def fromTuple(self, t):
    self.point_id = int(t[0])
    self.point_type = t[1]
    self.bank_id = int(t[2])
    self.town_id = int(t[3])
    self.longitude = float(t[4]) if t[4] is not None else None
    self.latitude = float(t[5]) if t[5] is not None else None
    self.address = t[6]
    self.address_comment = t[7]
    self.metro_name = t[8]
    self.free_access = int(t[9]) == 1
    self.main_office = int(t[10])
    self.without_weekend = int(t[11])
    self.round_the_clock = int(t[12]) == 1
    self.works_as_shop = int(t[13]) == 1
    self.schedule_general = t[14]
    self.schedule_private = t[15]
    self.schedule_vip = t[16]
    self.tel = t[17]
    self.additional = t[18]
    self.cash_in = t[19]

  def fromTupleNew(self, t):
    self.point_id = int(t[0]),
    self.point_type = t[1],
    self.bank_id = int(t[2]),
    self.town_id = int(t[3]),
    self.longitude = float(t[4]) if t[4] is not None else None,
    self.latitude = float(t[5]) if t[5] is not None else None,
    self.address,
    self.address_comment,
    self.metro_name,
    self.free_access,
    self.main_office,
    self.without_weekend,
    self.round_the_clock,
    self.works_as_shop,
    self.schedule_general,
    self.schedule_private,
    self.schedule_vip,
    self.tel,
    self.additional,
    self.rub,
    self.usd,
    self.eur,
    self.cash_in

def createJsonDataPrefetch(townId):
  return {
    "jsonrpc": "2.0",
    "method": "bankGeo/getObjectsByFilter",
    "params": {
       "with_empty_coordinates": True,
       "limit": batchSize,
       "type": ["office", "branch", "atm", "cash", "self_office"],
       "region_id": [townId]
    },
    "id": "2"
  }

def createJsonData(offset, townId):
  return {
    "jsonrpc": "2.0",
    "method": "bankGeo/getObjectsByFilter",
    "params": {
       "with_empty_coordinates": True,
       "limit": batchSize,
       "offset": offset,
       "type": ["office", "branch", "atm", "cash", "self_office"],
       "region_id": [townId]
     },
    "id": "2"
  }

# idList : stringList
def createJsonFullData(idList):
  return {
    "jsonrpc": "2.0",
    "method": "bank/getBankObjectsData",
    "params": {
        "id_list": idList
    },
    "id": "9"
  }
    
#{,,{"id_list":
#["4328310","7296301","7593802","7296298","1189208","495345","495378","495400",
#"495403","495375","495411","495382","495396","495409","495389","495355","548018",
#"6572679","6579419","6579439","6579443","6579444","6579445","6587966","6588499"]},}

def getCashPointsByRegionId(townId, printProgress):
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
  data = createJsonDataPrefetch(townId)
  
  r = requests.post(url, headers = headers, data = json.dumps(data))
  responseJson = r.json()
  total = int(responseJson['result']['total']);
  if total == 0:
    print('Zero total count received in prefetch for townId:', townId)
    return []

  print("townId: " + str(townId) + "; total:" + str(total))
  cashPointsList = []

  reqCount = total // batchSize
  #reqCount = 4
  doneCount = 0
  for i in range(0, reqCount + 1):
    data = createJsonData(i * batchSize, townId)
    #r = requests.post(url, headers = headers, data = json.dumps(data))
    #responseJson = r.json()
    #cashPoints = responseJson['result']['data']

    cashPoints = []
    for attempt_num in range(0, 5):
      cashPoints = getPostResponseJsonData(url, headers, data)
      if len(cashPoints) != 0:
        break
      else:
        time.sleep(5)

    if len(cashPoints) == 0:
      print('Empty idList for townId: ' + str(townId))
      continue
    
    idList = []
    for cp in cashPoints:
      idList.append(cp['id'])

    fullData = createJsonFullData(idList)
    #r = requests.post(url, headers = headers, data = json.dumps(fullData))
    #responseFullJson = r.json()
    #cashPoints = responseFullJson['result']['data']
    cashPoints = getPostResponseJsonData(url, headers, fullData)

    for cpJson in cashPoints:
      cp = CashPoint()
      cp.fromJsonData(cpJson)
      cashPointsList.append(cp)

    if True:
      doneCount += len(cashPoints)
      donePercent = round(float(doneCount) / float(total) * 100)
      print("[" + str(donePercent) + "%] " +  str(doneCount) + "/" + str(total), end = '\r'),


  return cashPointsList
    

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("town id is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("output db file is not specified")
    sys.exit(2)

  townId = int(sys.argv[1])
  outputDB = sys.argv[2]
  
  if os.path.isfile(outputDB):
    os.remove(outputDB)
    print('removed file:', outputDB)
    
  db = sqlite3.connect(outputDB)
  curs = db.cursor()
  curs.execute('CREATE TABLE cashpoints (id integer primary key, type text, bank_id integer, town_id integer, longitude real, latitude real, address text, address_comment text, metro_name text, free_access integer, main_office integer, without_weekend integer, round_the_clock integer, works_as_shop integer, schedule_general text, schedule_private text, schedule_vip text, tel text, additional text)')

  cashPointsList = getCashPointsByRegionId(townId, True)
  curs.executemany('INSERT INTO cashpoints VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [cp.toTuple() for cp in cashPointsList])
  
  db.commit()
  db.close()

#  r = requests.post(url, headers=headers, data=json.dumps(data));
#  responseJson = r.json()
#  print(responseJson)

#  'longitude', 'latitude', 'icon_url', 'is_main', 'address', 'name', 'bank_id', 'type'
  