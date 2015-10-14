#!/usr/bin/python3

import os, sys
import sqlite3
from cash_point_list_dumper import CashPoint

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("cp.db file is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("cp_processed.db file is not specified")
    sys.exit(2)

  cpDB = sys.argv[1]
  cpProcessedDB = sys.argv[2]

  if os.path.isfile(cpProcessedDB):
    os.remove(cpProcessedDB)
    print('removed file:', cpProcessedDB)

  cashPointsList = []

  db = sqlite3.connect(cpDB)
  curs = db.cursor()
  cashInIdList = set([int(row[0]) for row in curs.execute('SELECT id FROM cashpoints WHERE additional LIKE "%приема%"')])
  for row in curs.execute('SELECT id, type, bank_id, town_id, longitude, latitude, address, address_comment, metro_name, free_access, main_office, without_weekend, round_the_clock, works_as_shop, schedule_general, schedule_private, schedule_vip, tel, additional FROM cashpoints'):
    cp = CashPoint()
    hasCashIn = int(row[0]) in cashInIdList
    cp.fromTuple(row + (hasCashIn,))
    cashPointsList.append(cp)
  db.close()

  db = sqlite3.connect(cpProcessedDB)
  curs = db.cursor()
  curs.execute('CREATE TABLE cashpoints (id integer primary key, type text, bank_id integer, town_id integer, longitude real, latitude real, address text, address_comment text, metro_name text, free_access integer, main_office integer, without_weekend integer, round_the_clock integer, works_as_shop integer, schedule_general text, schedule_private text, schedule_vip text, tel text, additional text, rub integer, usd integer, eur integer, cash_in integer)')
  curs.executemany('INSERT INTO cashpoints VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [cp.toTupleNew() for cp in cashPointsList])
  db.commit()
  db.close()
