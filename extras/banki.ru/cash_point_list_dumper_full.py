#!/usr/bin/python3

import os, sys
import sqlite3
from cash_point_list_dumper import getCashPointsByRegionId

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("towns.db file is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("output.db file is not specified")
    sys.exit(2)

  townsDB = sys.argv[1]
  outputDB = sys.argv[2]

  appendStartId = 0
  if len(sys.argv) == 4:
    appendStartId = int(sys.argv[3])

  if not os.path.isfile(townsDB):
    print("No such file: " + townsDB)
    sys.exit(3)

  if os.path.isfile(outputDB) and appendStartId == 0:
    os.remove(outputDB)
    print('removed file:', outputDB)

  db = sqlite3.connect(townsDB)
  curs = db.cursor()
  townIdList = [row[0] for row in curs.execute('SELECT id FROM towns')]
  db.close()

  if len(townIdList) == 0:
    print("Empty list of town ids: no such data to fetch")
    sys.exit(4)

  db = sqlite3.connect(outputDB)
  curs = db.cursor()

  if appendStartId == 0:
    curs.execute('CREATE TABLE cashpoints (id integer primary key, type text, bank_id integer, town_id integer, longitude real, latitude real, address text, address_comment text, metro_name text, free_access integer, main_office integer, without_weekend integer, round_the_clock integer, works_as_shop integer, schedule_general text, schedule_private text, schedule_vip text, tel text, additional text)')

  #print(townIdList)

  totalCount = townIdList[-1]
  for townId in townIdList:
    if townId < appendStartId:
       print("skipping townid: " + str(townId))
       continue
    try:
      cashPointsList = getCashPointsByRegionId(townId, False)
      curs.executemany('INSERT INTO cashpoints VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [cp.toTuple() for cp in cashPointsList])
      db.commit()
      donePercent = round(float(townId) / float(totalCount) * 100)
      print("[" + str(donePercent) + "%] " +  str(townId) + "/" + str(totalCount))
    except:
      print('failed on townid: ' + str(townId))
      raise

  db.close()
  #db = sqlite3.connect(outputDB)
