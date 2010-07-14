data='''CMD_REQ = 0
CMD_RES = 1

BPHIT=0 
GETBPS=1  
SETBPS = 2  
GETREGS = 3 
SETREGS = 4 
READMEM = 5 
WRITEMEM = 6 


IDA_CMD = 7 
IDA_GETNAME=0
IDA_MAKECOMMENT=1
IDA_MAKEBYTE=2
IDA_MAKEWORD=3
IDA_MAKEDWORD=4
IDA_MAKEQWORD=5
IDA_MAKEOWORD=6
IDA_MAKEALIGN=7
IDA_MAKEFLOAT=8
IDA_MAKESTRING=9
IDA_MAKEDOUBLE=10
IDA_MAKECODE=11
IDA_MAKENAME=12
IDA_JUMPTO=13
IDA_SCREENEA=14
IDA_AAREA=15'''

dict_str = "%s={%s}"
template_dtos = "%s:'%s'"
template_stod = "'%s':%s"
delimiter = ",\n"
dict_vals = []
dict_name = "ida_lookup"

for i in data.split("\n"):
    if i.strip() == "":
        continue
    lh,rh = [j.strip() for j in i.split('=')]
    print lh, rh
    if lh.find("_") > 0:
        lh = lh.split("_")[1].lower()
    dict_vals.append(template_dtos%(rh,lh))
    dict_vals.append(template_stod%(lh,rh))

print dict_str%(dict_name,delimiter.join(dict_vals))
    
    