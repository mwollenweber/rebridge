
import gtk
import gtk.gdk as gdk
import vwidget.util as vw_util
from ConfigParser import ConfigParser

class VView(gtk.ScrolledWindow):

    __display_name__ = "Stuff!"

    def __init__(self, closable=True):
        gtk.ScrolledWindow.__init__(self)
        self.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.vwactive = True
        self.vwname = None
        self.closable = closable
        self.connect("destroy", self.vwDestroy)

    def vwDestroy(self, arg):
        pass

    def vwSetSensitive(self, sensitive=True):
        """
        Set this view object as "sensitive" to user input
        """
        if self.vwactive != sensitive:
            self.vwactive = sensitive
            self.set_sensitive(sensitive)

    def vwGetDisplayName(self):
        if self.vwname == None:
            return self.__class__.__display_name__
        return self.vwname

    def vwSetDisplayName(self, name):
        self.vwname = name

    def vwGetViewName(self):
        return self.__class__.__name__

    def vwIsClosable(self):
        return self.closable

    def vwSetClosable(self, closable):
        self.closable = closable

class GladeView(VView):
    """
    Use a glade file to define "views" with the same name as the class
    (
    """
    def __init__(self, gladefile):
        VView.__init__(self)
        self.vwglade = gtk.glade.XML(gladefile)
        self.vwglade.signal_autoconnect(self)
        win = self.vwglade.get_wiget(self.__class__.__name__)
        frame = win.get_child()
        p = view.get_parent()
        if p != None:
            p.remove(frame)
        win.destroy()
        self.add(frame)

    def vwGetWidget(self, name):
        return self.vwglade.get_widget(name)

class VTreeView(VView):

    __model_class__ = gtk.ListStore
    # Some example column definitions
    __cols__ = (
        (None, 0, object),
        ("Address",1, str),
        ("Stuff",2, str)
    )

    def __init__(self):
        VView.__init__(self)
        self.treeview = gtk.TreeView()
        self.treeview.connect("row_activated", self.vwActivated)
        cols = self.vwGetColumns()
        self.vwInitModel(cols, self.__model_class__)
        self.add(self.treeview)
        self.vwLoad()

    def vwGetColumns(self):
        return self.__cols__

    def vwInitModel(self, cols, modelclass):
        # Remove any old columns
        for col in self.treeview.get_columns():
            self.treeview.remove_column(col)

        ftypes = []
        for name,index,ctype in cols:
            ftypes.append(ctype)
            if name == None:
                continue
            col = vw_util.makeColumn(name, index)
            self.treeview.append_column(col)

        self.model = modelclass(*ftypes)
        self.treeview.set_model(self.model)

    def vwLoad(self):
        # Over-ride this to cause a load from scratch
        pass

    def vwClear(self):
        # This clears the view
        self.model.clear()

    def vwRemove(self, iter):
        self.model.remove(iter)

    def vwActivated(self, tree, path, column):
        # over-ride this for activation callbacks
        pass

    def vwGetSelected(self, column):
        """
        Get the selected row's column by index
        """
        return vw_util.getTreeSelected(self.treeview, column)

class VTextView(VView):

    def __init__(self):
        VView.__init__(self)
        self.textview = gtk.TextView()
        self.textview.connect("populate_popup", self.vwGetPopup)
        self.add(self.textview)

        self.tagtable = gtk.TextTagTable()
        self.textbuf = gtk.TextBuffer(self.tagtable)
        self.textview.set_buffer(self.textbuf)

        style = gtk.Style()

        style.base[gtk.STATE_NORMAL] = gdk.Color(0,0,0)
        style.text[gtk.STATE_NORMAL] = gdk.Color(0,0,0xff)

        style.base[gtk.STATE_INSENSITIVE] = gdk.Color(0,0,0)
        style.text[gtk.STATE_INSENSITIVE] = gdk.Color(20,20,20)

        self.textview.set_style(style)

        self.tagcfg = ConfigParser()

        self.curtag = None # Is a current tag selected?
        self.deftag = gtk.TextTag("default")
        self.vwInitTag(self.deftag)

        start,end = self.textbuf.get_bounds()
        self.textbuf.create_mark("insertend", end)

    def vwInitTag(self, tag, typename="default", handler=None):
        """
        Initialize a tag for event processing and properties from
        the tag config.
        """
        if handler != None:
            tag.connect("event", handler)
        self.tagtable.add(tag)
        tag.reversed = False
        self.vwSetTagColor(tag, typename=typename)

    def vwSetTagColor(self, tag, typename="default"):
        if self.tagcfg.has_section(typename):
            for name in self.tagcfg.options(typename):
                tag.set_property(name, self.tagcfg.get(typename,name))
        else:
            tag.set_property("font", "Monospace 10")
            tag.set_property("foreground", "green")
            tag.set_property("background", "black")

    def vwTagSelector(self, tag, textview, event, iter):
        """
        Use this as the event handler for tag events on exclusivly
        selectable tags.
        """
        if event.type == gdk.BUTTON_PRESS:
            if tag.get_property("name") != "default":
                if self.curtag != None:
                    self.vwReverseTag(self.curtag)
                self.vwReverseTag(tag)
                self.curtag = tag
                return True

    def vwLoadTags(self, tagfile):
        self.tagcfg.read(tagfile)
        for sec in self.tagcfg.sections():
            tag = self.vwGetTag(sec)
            if tag == None:
                tag = gtk.TextTag(sec)
                self.tagtable.add(tag)

            tag.connect("event",self.vwTagEvent)
            for name in self.tagcfg.options(sec):
                val = self.tagcfg.get(sec,name)
                if val.isdigit():
                    val = int(val)
                tag.set_property(name, val)

    def vwGetTag(self, name=None):
        if name == None:
            name = "default"
        return self.tagtable.lookup(name)

    def vwTagEvent(self, tag, textview, event, iter):
        #print "OVERRIDE ME FOR TAG EVENT PROCESSING!"
        pass

    def vwReverseTag(self, tag):
        """
        fg->bg bg->fg highlighting
        """
        front = tag.get_property("foreground-gdk")
        back = tag.get_property("background-gdk")
        tag.set_property("foreground-gdk", back)
        tag.set_property("background-gdk", front)
        tag.reversed = not tag.reversed

    def vwGetPopup(self, textview, menu):
        """
        Over-ride this to add elements to the right click menu on click.
        """
        #mn = gtk.MenuItem("Example!")
        #mn.connect("activate", self.doexample)
        #mn.show()
        #menu.prepend(mn)
        pass

    def vwInsertText(self, text, iter=None, tagname=None, tag=None):
        if iter == None:
            iter = self.textbuf.get_end_iter()
        if tagname == None and tag == None:
            self.textbuf.insert(iter, text)
        else:
            if tagname != None:
                tag = self.tagtable.lookup(tagname)
            self.textbuf.insert_with_tags(iter, text, tag)
        self.textbuf.move_mark_by_name("insertend", iter)

    def vwScrollToBottom(self):
        mark = self.textbuf.get_mark("insertend")
        self.textview.scroll_to_mark(mark,0)

    def vwScrollToTop(self):
        start,end = self.textbuf.get_bounds()
        self.textview.scroll_to_iter(start, 0)

    def vwClearText(self):
        start,end = self.textbuf.get_bounds()
        self.textbuf.delete(start, end)
    
    def vwGetAppendIter(self):
        return self.textbuf.get_end_iter()

