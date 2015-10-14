#!/usr/bin/python3

import sys
import json
import sqlite3

from flask import Flask
from flask import Response

app = Flask(__name__)

town_db_path = ""
cp_db_path = ""

town_db = None
cp_db = None

town_db_curs = None
cp_db_curs = None

def responseJson(res_json):
  data = json.dumps(res_json)
  return Response(data,
                  status = 200,
                  mimetype = 'application/json')

@app.route('/')
def hello_world():
  return 'Hello world!'

@app.route('/town/<int:id>', methods = ['GET'])
def town(id):
  global town_db
  global town_db_curs

  if not town_db_curs:
    town_db = sqlite3.connect(town_db_path)
    town_db_curs = town_db.cursor()

  town_db_curs.execute('SELECT id, name, name_tr, latitude, longitude, zoom FROM towns WHERE id = ?', [str(id)])
  row = town_db_curs.fetchone()
  json = None
  if row:
    json = {
                   "id" : row[0],
                 "name" : row[1],
              "name_tr" : row[2],
            "region_id" : row[3],
      "regional_center" : row[4],
             "latitude" : row[5],
            "longitude" : row[6],
                 "zoom" : row[7]
    }
  else:
    json = { "id" : None }
  return responseJson(json)

@app.route('/cashpoint/<int:id>', methods = ['GET'])
def cashpoints(id):
  global cp_db
  global cp_db_curs

  if not cp_db_curs:
    cp_db = sqlite3.connect(cp_db_path)
    cp_db_curs = cp_db.cursor()

  cp_db_curs.execute('SELECT id, type, bank_id, town_id, longitude, latitude, address, address_comment, metro_name, free_access, main_office, without_weekend, round_the_clock, works_as_shop, schedule_general, schedule_private, schedule_vip, tel, additional, rub, usd, eur, cash_in')

  json = {
    "id" : id
  }
  return responseJson(json)

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print("town.db file is not specified")
    sys.exit(1)

  if len(sys.argv) < 3:
    print("cp.db file is not specified")
    sys.exit(2)

  town_db_path = sys.argv[1]
  cp_db_path = sys.argv[2]

  app.run(debug=True)
#  app.run(host='0.0.0.0')
