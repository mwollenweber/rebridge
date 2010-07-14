data='''IDA_GETNAME:["long"],
IDA_MAKECOMMENT:["long","str"],
IDA_MAKEBYTE:["long"],
IDA_MAKEWORD:["long"], 
IDA_MAKEDWORD:["long"],
IDA_MAKEQWORD:["long"],
IDA_MAKEOWORD:["long"],
IDA_MAKEALIGN:["long","int","int"],
IDA_MAKEFLOAT:["long"],
IDA_MAKEOWORD:["long"],
IDA_MAKEOWORD:["long"],
IDA_MAKENAME:["long","str"],
IDA_SCREENEA:["long"],
IDA_JUMPTO:["long"],
IDA_AAREA:["long","long"],
IDA_MAKEFLOAT:["long","long"]'''

dict_str = "%s={%s}"
template_dtos = "%s:'%s'"
template_stod = "'%s':%s"
delimiter = "\n"
dict_vals = []
dict_name = "ida_lookup"

for i in data.split("\n"):
    if i.strip() == "":
        continue
    lh,rh = [j.strip() for j in i.split(':')]
    print lh, rh
    if lh.find("_") > 0:
        lh = lh.split("_")[1].lower()
    #dict_vals.append(template_dtos%(rh,lh))
    dict_vals.append(template_stod%(lh,rh))

print dict_str%(dict_name,delimiter.join(dict_vals))
    
def print_templates(data, cmd_typ):
    for i in data.splitlines():
        v,t = v,t = i.split(":")
        t = "".join(t.strip(',')[1:-1])
        print "char* "+v+"_"+cmd_typ+"_TEMPLATE[] = {"+",".join([j.replace("'",'"') for j in t.split(",")])+',"\\0"};'
        
def print_empty_templates(data, cmd_typ):
    for i in data.splitlines():
        v,t = v,t = i.split(":")
        t = "".join(t.strip(',')[1:-1])
        print "char* "+v+"_"+cmd_typ+'_TEMPLATE[] = {"\\0"};'


def derive_cmd_def(templates):
    cmd_t = '&CMD_DEF(%s, "%s", (char **)%s, (char **)%s);'
    cmds = []
    # cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE"
    for i in templates:
        if i == "":
            continue
        cmd = i.split(" ")[1].split("_")[0]
        cmds.append(cmd_t%(cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE"))
        print cmd_t%(cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE")
    return cmds
    
def derive_idacmd_def(templates):
    cmd_t = '&CMD_DEF(%s, "%s", (char **)%s, (char **)%s);'
    cmds = []
    # cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE"
    for i in templates:
        if i == "":
            continue
        print i
        cmd = "_".join(i.split(" ")[1].split("_")[0:-2])
        cmds.append(cmd_t%(cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE"))
        print cmd_t%(cmd, cmd.lower(), cmd+"_REQ_TEMPLATE", cmd+"_RSP_TEMPLATE")
    return cmds