#!/bin/bash

wget 'http://www.banki.ru/bitrix/components/banks/universal.select.region/ajax.php?bankid=0&baseUrl=%2Fbanks%2F&appendUrl=%2Flist%2F&type=city' \
      --output-document=data/towns.json.esc

native2ascii -encoding UTF-8 -reverse data/towns.json.esc data/towns.json
rm data/towns.json.esc

