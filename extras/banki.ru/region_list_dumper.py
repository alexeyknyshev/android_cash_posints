#!/usr/bin/python3

import os, sys, sqlite3
import json
import requests
import time

def getNameTrFromRegionUrl(regionUrl):
  nameTr = regionUrl
  l = regionUrl.split('/')
  if len(l) > 1:
    nameTr = l[1]
  return nameTr

def transliterate(in_str):
  tr_map = {
    "а" : "a", "А" : "A",
    "б" : "b", "Б" : "B",
    "в" : "v", "В" : "V",
    "г" : "g", "Г" : "G",
    "д" : "d", "Д" : "D",
    "е" : "e", "Е" : "E",
    "ё" : "e", "Ё" : "E",
    "ж" : "j", "Ж" : "J",
    "з" : "z", "З" : "Z",
    "и" : "i", "И" : "I",
    "й" : "iy","Й" : "Iy",
    "к" : "k", "К" : "K",
    "л" : "l", "Л" : "L",
    "м" : "m", "М" : "M",
    "н" : "n", "Н" : "N",
    "о" : "o", "О" : "O",
    "п" : "p", "П" : "P",
    "р" : "r", "Р" : "R",
    "с" : "s", "С" : "S",
    "т" : "t", "Т" : "T",
    "у" : "u", "У" : "U",
    "ф" : "f", "Ф" : "F",
    "х" : "h", "Х" : "H",
    "ц" : "ts","Ц" : "Ts",
    "ч" : "ch","Ч" : "Ch",
    "ш" : "sh","Ш" : "Sh",
    "щ" : "sh","Щ" : "Sh",
    "ъ" : "",  "Ъ" : "",
    "ы" : "i", "Ы" : "I",
    "ь" : "",  "Ь" : "",
    "э" : "e", "Э" : "E",
    "ю" : "iu","Ю" : "Iu",
    "я" : "ia","Я" : "Ia"
  }
  result = ""
  for c in in_str:
    if c in tr_map:
      result = result + tr_map[c]
    else:
      result = result + c
  return result

class Town:
  def __init__(self):
    self.townid = 0
    self.name = ""
    self.name_tr = ""
    self.region_id = 0
    self.regional_center = 0
    self.latitude = 0.0
    self.longitude = 0.0
    self.zoom = 0
    self.has_emblem = 0

  def fromJsonData(self, data):
    self.townid          = data['id']
    self.name            = data['name']
    self.name_tr         = transliterate(data['name'])
    #self.region_id       = data['parent_id']
    self.regional_center = data['is_regional_center']
    self.latitude        = data['latitude']
    self.longitude       = data['longitude']
    self.zoom            = int(data['zoom']) if data['zoom'] else 12
    self.has_emblem      = 1 if len(data['emblem_url']) > 0 else 0

  def toTuple(self):
    return (self.townid, self.name, self.name_tr, self.region_id, self.regional_center, self.latitude, self.longitude, self.zoom, self.has_emblem)

class Region:
  def __init__(self):
    self.regionid = 0
    self.name = ""
    self.name_tr = ""
    self.latitude = 0.0
    self.longitude = 0.0
    self.zoom = 0

  def fromJsonData(self, data):
    self.regionid  = data['id']
    self.name      = transliterate(data['name'])
    self.name_tr   = getNameTrFromRegionUrl(data['region_url'])
    self.latitude  = data['latitude']
    self.longitude = data['longitude']
    self.zoom      = int(data['zoom']) if data['zoom'] else 12

  def toTuple(self):
    return (self.regionid, self.name, self.name_tr, self.latitude, self.longitude, self.zoom)

def makeDBRow(town):
  l = town['region_code'].split('/')

  #regionCenter = False
  latinName = town['region_code']

  if len(l) > 1:
    #regionCenter = True
    latinName = l[1]
    latinName = latinName.replace('~', '').replace('_', ' ').replace('tss', 'z').replace('ssh', 'sh')

  #townName = town['region_name_full'];
  regionName = ""
  l = town['region_name_full'].split('(')
  if len(l) > 1:
    #townName = l[0].strip()
    regionName = l[1].replace(')', '').strip()

  return (town['region_id'], town['region_name'], latinName, regionName)

def createHeaderData():
  return {
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

def createJsonData(regionId):
  return {
    "jsonrpc": "2.0",
    "method": "region/get",
    "params": {
      "id": regionId
    },
    "id": "1"
  }

def getPostResponseJsonData(url, headerData, reqData):
  data = None

  for attempt_num in range(0, 5):
    r = requests.post(url, headers = headerData, data = json.dumps(reqData))
    responseJson = r.json()
    try:
      data = responseJson['result']['data']
      break
    except KeyError:
      try:
        errorMsg = responseJson['error']['message']
        print("  Error: " + errorMsg)
        print("Attempt: " + str(attempt_num))
        time.sleep(5)
        continue
      except:
        print(responseJson)
        raise

  return data

def fillDataContainers(townsList, regionsMap, townData):
  town = Town()
  town.fromJsonData(townData)

  parentId = townData['parent_id']

  if not parentId in regionsMap:
    reqData = createJsonData(parentId)
    r = requests.post(url, headers = headerData, data = json.dumps(reqData))
    responseJson = r.json()
    regionData = getPostResponseJsonData(url, headerData, reqData)

    region = Region()
    region.fromJsonData(regionData)
    if region.name_tr != "Drugie":
      regionsMap[parentId] = region
    else:
      town.region_id = 0

  townsList.append(town)

def resolveTownNameDup(townsList, regionsMap):
  townNameSet = set()
  dupNameSet = set()
  for town in townsList:
    if not town.name in townNameSet:
      townNameSet.add(town.name)
    else:
      dupNameSet.add(town.name)

  for index, town in enumerate(townsList):
    if town.name in dupNameSet:
      if town.region_id in regionsMap:
        town.name = town.name + " (" + regionsMap[town.region_id].name + ")"
      else:
        print("Error: Dup town.name for town without region_id\n" + str(town.name))

def getRegionNameByCoord(longitude, latitude):
  geoUrlMask = "http://geocode-maps.yandex.ru/1.x/?format=json&geocode=%f,%f&lang=ru-RU&key=e5994ba3-c5d2-4158-ab34-65800ab35e27"
  url = geoUrlMask % (longitude, latitude)
  r = requests.get(url)
  responseJson = r.json()

  featureMember = responseJson['response']['GeoObjectCollection']['featureMember']
  for geoObj in featureMember:
    try:
      geoObjInternal = geoObj['GeoObject']
      addrDet = geoObjInternal['metaDataProperty']['GeocoderMetaData']['AddressDetails']
      return addrDet['Country']['AdministrativeArea']['AdministrativeAreaName']
    except KeyError:
      continue

  errStr = "AdministrativeAreaName has not found in geocode response:\n\trequest: " + url + "\n\tresponse:\n" + str(responseJson)
  print(errStr, file=sys.stderr)
  return 0

def getRegionIdByName(regionsMap, regionName, index):
  for (region_id, region_name) in regionsMap.items():
    if region_name == regionName:
      return region_id

  if index in regionsMap:
    sys.exit("getRegionIdByName: attempt to override existing index")

  regionsMap[index] = regionName
  return index

def fetchRegions(townsList, regionsMap):
  regionNewIndex = 1
  requestIndex = 1
  for idx, town in enumerate(townsList):
    if town.region_id == 0 or not town.region_id in regionsMap:
      try:
        region_name = getRegionNameByCoord(latitude  = float(town.latitude),
                                           longitude = float(town.longitude))
        requestIndex += 1

      except TypeError:
        print("skipped region decoding for town: " + town.name, file=sys.stderr)
        town.region_id = 0
        town.latitude = 0.0
        town.longitude = 0.0
        townsList[idx] = town

      except requests.exceptions.ConnectionError:
        print("failed ya geo api request " + str(requestIndex), file=sys.stderr)
        raise

      while regionNewIndex in regionsMap:
        regionNewIndex += 1

      town.region_id = getRegionIdByName(regionsMap, region_name, regionNewIndex)
      townsList[idx] = town

if __name__ == "__main__":
  #print(transliterate('Съешь ещё этих мягких французских булок да выпей чаю'))
  #print(getRegionNameByCoord(latitude = 55.855542, longitude = 38.441157))
  #sys.exit(0)

  if len(sys.argv) < 2:
    print("regions json file is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("output db file is not specified")
    sys.exit(2)

  regionsJson = sys.argv[1]
  outputDB = sys.argv[2]

  if os.path.isfile(outputDB):
    os.remove(outputDB)
    print('removed file:', outputDB)

  index = 1
  tuple_index = 1
  count = 0

  townsList = []
  regionsMap = {}

  jsonData = ""
  with open(regionsJson, "r", encoding="utf8") as regionsJsonFile:
    jsonData = regionsJsonFile.read()

  jsonTree = json.loads(jsonData);
  data = jsonTree['data']

  url = "http://www.banki.ru/api/"
  headerData = createHeaderData()

  currentIndex = 500
  currentIndexStep = 500

  for t in data:
    row = makeDBRow(t)

    townId = int(row[0])

    if townId >= currentIndex:
      currentIndex += currentIndexStep
      print("processing town id: " + str(townId))

    reqData = createJsonData(townId)
    townData = getPostResponseJsonData(url, headerData, reqData)

    if townData:
      fillDataContainers(townsList, regionsMap, townData)

  fetchRegions(townsList, regionsMap)
  resolveTownNameDup(townsList, regionsMap)

  bd = sqlite3.connect(outputDB)
  c = bd.cursor()
  c.execute('CREATE TABLE towns (id integer primary key, name text, name_tr text, region_id integer, regional_center integer, latitude real, longitude real, zoom integer, has_emblem integer)')
  c.executemany('INSERT INTO towns VALUES (?,?,?,?,?,?,?,?,?)', [town.toTuple() for town in townsList])

  c.execute('CREATE TABLE regions (id integer primary key, name text, name_tr text, latitude real, longitude real, zoom integer)')
  c.executemany('INSERT INTO regions VALUES (?,?,?,?,?,?)', [region.toTuple() for region in regionsMap.values()])
  bd.commit()
  bd.close()

  #print("Total count: ", count)
