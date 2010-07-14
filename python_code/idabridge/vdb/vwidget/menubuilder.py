
import gtk

class FieldAdder:
    def __init__(self):
        self.kids = {}

    def addField(self, pathstr, callback=None, args=()):
        parent = self
        kid = None
        plist = pathstr.split(".")

        for p in plist[:-1]:
            kid = parent.kids.get(p)
            if kid == None:
                item = gtk.MenuItem(p, True)
                item.set_name("vwidget_menu")
                item.show()
                parent.append(item)
                kid = Menu()
                item.set_submenu(kid)
                parent.kids[p] = kid
            parent = kid

        item = gtk.MenuItem(plist[-1], True)
        if callback != None:
            item.connect("activate", callback, *args)
        item.show()
        item.set_name("vwidget_menu")
        parent.append(item)
        return item

class MenuBar(FieldAdder, gtk.MenuBar):
    def __init__(self):
        gtk.MenuBar.__init__(self)
        FieldAdder.__init__(self)
        self.set_name("vwidget_menu")

class Menu(FieldAdder, gtk.Menu):
    def __init__(self):
        gtk.Menu.__init__(self)
        FieldAdder.__init__(self)
        self.set_name("vwidget_menu")

