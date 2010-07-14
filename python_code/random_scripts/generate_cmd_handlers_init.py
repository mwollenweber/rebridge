

def create_aliases(item):
    #print item
    name = item.split('.')[1]
    aliases = [item,name,name.lower()]
    return ",".join(aliases)
#commented this out

def create_ida_aliases():
    fname = """C:\\code\\idabridge\\python_code\\ida_ida_funcs.txt"""
    f = open(fname).readlines()
    create_alias_list = ['"'+create_aliases(i.strip())+'"' for i in f]
    define_char_array = 'char *IDAPYTHON_ALIASES[]={%s,""};'
    return define_char_array%(",\n".join(x))


def get_init_handler_funcs(data):
    cleanup = [" ".join(i.split()[1:]).split("(")[0] for i in data.splitlines() if i != ""]
    cleanup.sort()
    funcs = {}
    for i in cleanup:
        n = "".join(i.split("_")[:-1])
        funcs[n] = ["default_net_handler","default_net_handler","default_cli_handler"]
    for i in cleanup:
        x = i.split("_")[-1]
        n = "".join(i.split("_")[:-1])
        if x == 'cli':
            funcs[n][2] = i
        elif x == 'rsp':
            funcs[n][1] = i
        elif x == 'req':
            funcs[n][0] = i
    return funcs

#cmd_handler = "register_cmd_handler(%s, %s);"
#cli_handler = "register_cli_handler(%s, %s);"
def print_init_handler_funcs(funcs):
    cli_cmd_handler =  'register_cmd_handler("%s", %s, %s, %s );'
    for k in funcs:
        a,b,c = funcs[k]
        n = "".join(k.split("_")[:2])
        print "\n// %s cmd and cli handler registration"%(n)
        print cli_cmd_handler%(n,a,b,c)

def do_all_data(data):
    funcs = get_init_handler_funcs(data)        
    print_init_handler_funcs(funcs)
    return funcs








