#!/usr/bin/python3

import os, sys, sqlite3
from bs4 import BeautifulSoup

class Bank:
  def __init__(self):
    self.name = ""             # bank name
    self.url = ""              # internal banki.ru url
    self.tel = ""              # tel number
    self.tel_description = ""  # tel number description
    self.licence = ""          # bank licence number
    
  def setTel(self, telStr):
    if len(telStr) == 0:
      self.tel = telStr
    
    res = ""
    for c in telStr:
      if c.isdigit() or c == '+':
        res += c
    if len(res) == 10:
      res = "8" + res
    self.tel = res
    
  def setTelDescription(self, telDescrStr):
    telDescrStr = telDescrStr.replace(' (звонок по России бесплатный)', '')
    telDescrStr = telDescrStr.replace('звонок по России бесплатный', '')
    self.tel_description = telDescrStr

  def __str__(self):
    return "\tname\t\t= %s\n\turl\t\t= %s\n\ttel\t\t= %s\n\ttel_descr\t= %s\n\tlicence\t= %s" % (self.name, self.url, self.tel, self.tel_description, self.licence)
  
  def __repr__(self):
    return "\n{\n" + self.__str__() + "}"
  
  def toTuple(self):
    return (self.name, self.url, self.tel, self.tel_description, self.licence)

#def parseBankSiteUrl

def parseHtmlData(data):
  result = []
  #print("=====================================================")
  #print(data)
  soup = BeautifulSoup(data)
  table = soup.find('table', attrs={'class':"standard-table standard-table--row-highlight"})
  #print(table)
  bank_entries = table.find_all('tr')
  #print(bank_entries)
  for bank in bank_entries:
    #print(bank)
    bank_name = bank.find('a', attrs={'class':"widget__link"})
    if bank_name is None:
      bank_name = bank.find('span', attrs={'class':"widget__link color-gray-gray"})
    
    bank_span = bank.find_all('span')
    bank_tel_descr = ""
    bank_tel = ""
    bank_url = ""
    bank_licence = ""
    for span in bank_span:
      if len(span.attrs) == 0:
        licence_list = [s for s in span.getText().split() if s.isdigit()]
        if len(licence_list) != 0:
          bank_licence = licence_list[0]

      if span.has_attr('title'):
        bank_tel_descr = span['title']
        bank_tel = span.getText()
      
    if bank_name.has_attr('href'):
      bank_url = bank_name['href']
      
    bank = Bank()
    bank.name = bank_name.getText().replace(u'\xa0', u' ')
    bank.url  = bank_url
    bank.setTel(bank_tel)
    bank.setTelDescription(bank_tel_descr)
    bank.licence = bank_licence
    
    result.append(bank)
  
  return result

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("data dir is not specified")
    sys.exit(1)
    
  if len(sys.argv) < 3:
    print("output db file is not specified")
    sys.exit(2)
    
  dataDir = sys.argv[1]
  outputDB = sys.argv[2]
  
  if os.path.isfile(outputDB):
    os.remove(outputDB)
    print('removed file:', outputDB)
  
  cwd = os.getcwd()
  index = 1
  tuple_index = 1
  count = 0
  
  bd = sqlite3.connect(outputDB)
  c = bd.cursor()
  c.execute('CREATE TABLE banks (id integer primary key autoincrement, name text, url text, tel text, tel_description text, licence integer unique)')
  
  prepared_tuples = []
  
  for (dirname, _2, files) in os.walk(dataDir):
    files.sort(key=lambda x: os.stat(os.path.join(dirname, x)).st_mtime)
    for f in files:
      if not f.endswith('html'):
        continue

      path = os.path.join(dirname, f)
      print('processing:', path)
      try:
        data = parseHtmlData(open(path, 'r').read())
      except UnicodeDecodeError:
        print('failed to read file: ' + path)
        raise

      for bank in data:
        prepared_tuples.append((tuple_index,) + bank.toTuple())
        tuple_index += 1
      count += len(data)
      index += 1
  
  #print(prepared_tuples)
  c.executemany('INSERT OR IGNORE INTO banks VALUES (?,?,?,?,?,?)', prepared_tuples)
  bd.commit()
  bd.close()
      
  print("Total count: ", count)