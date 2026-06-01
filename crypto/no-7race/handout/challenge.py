import sys
sys.set_int_max_str_digits(1000000)

flag = open("flag.txt","rb").read()
if len(flag) > 50:
    exit()

a = int.from_bytes(open("flag.txt","rb").read(), byteorder='big')

b = a << 77777
b = str(b)
if not b.endswith('03081127692533913997381228658418928780421416188103339458770036280397929450297959557812089439331054492922876854076547798835969658432397983993314299716042752'):
    exit()

