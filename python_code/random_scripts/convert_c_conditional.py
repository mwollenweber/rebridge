data = '''    if(cmd == "make_byte" || cmd =="mb")
        return IDA_MAKEBYTE;
    else if(cmd == "make_word" || cmd =="mw")
        return IDA_MAKEWORD;
    else if(cmd == "make_dword" || cmd =="md")
        return IDA_MAKEDWORD;
    else if(cmd == "make_qword" || cmd =="mq")
        return IDA_MAKEQWORD;
    else if(cmd == "make_oword" || cmd =="mo")
        return IDA_MAKEOWORD;
    else if(cmd == "make_double" || cmd =="mdbl")
        return IDA_MAKEDOUBLE;
    else if(cmd == "make_float" || cmd =="mf")
        return IDA_MAKEFLOAT;
    else if(cmd == "make_string" || cmd =="ms")
        return IDA_MAKESTRING;
    else if(cmd == "make_comment" || cmd =="mt")
        return IDA_MAKECOMMENT;
    else if(cmd == "make_code" || cmd =="mt")
        return IDA_MAKECODE;
    else if(cmd == "make_name" || cmd =="mn")
        return IDA_MAKENAME;
    else if(cmd == "make_align" || cmd =="ma")
        return IDA_MAKEALIGN;
    else if(cmd == "get_name" || cmd =="gn")
        return IDA_GETNAME;
    else if(cmd == "jumpto" || cmd =="jt")
        return IDA_JUMPTO;
    else if(cmd == "screenea" || cmd =="sa")
        return IDA_SCREENEA;
    else if(cmd == "umake_name" || cmd =="un")
        return IDA_UNDEFINENAME;
    else if(cmd == "umake_comment" || cmd =="uc")
        return IDA_UNDEFINECOMM;
    else if(cmd == "make_unknown" || cmd =="mu")
        return IDA_MAKEUNKNOWN;
    else if(cmd == "aarea" || cmd =="aa")
        return IDA_AAREA;
    else
        return -1;'''
        
dict_str = "%s={%s}"
template_dtos = "%s:'%s'"
template_stos = "%s:'%s'"
template_stol = "'%s':[%s]"
delimiter = ",\n"
dict_vals = []
dict_name = "ida_lookup"

for i in data.split("\n"):
    print i
    if i.strip() == "" or i.find("(") == -1:
        continue
    i = i.split("(")[1].split(")")[0]
    lh,rh = [j.split("==")[1].replace('"','').strip() for j in i.split('||')]
    values = [lh,rh]
    print lh, rh
    if lh.find("_") > 0:
        values.append(lh.replace("_", ''))
    for i in values:
        dict_vals.append(template_stos%("'"+i+"'",lh.replace("_",'')))
    #dict_vals.append(template_stod%(lh,rh))

print "".join(dict_str%(dict_name,delimiter.join(dict_vals)))