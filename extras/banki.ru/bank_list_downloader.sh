#!/bin/bash

echo "started downloading..."
for i in {1..16}
do
  url="http://www.banki.ru/banks/?order=fin_rating&PAGEN_1=$i"
  output="data/bank_list_data/page_$i.html.cp1251"
  result="data/bank_list_data/page_$i.html"
  wget "$url" --output-document="$output"
  if [ $? -eq 0 ]
  then
    echo "[OK] \"$url\" => \"$output\""
    iconv -f CP1251 -t UTF-8 "$output" > "$result"
    echo "--- UTF-8 reencoded => \"$result\""
    rm -f "$output"
  else
    echo "[FAIL] \"$url\" => \"$output\""
  fi
done
echo "downloading finished!"
