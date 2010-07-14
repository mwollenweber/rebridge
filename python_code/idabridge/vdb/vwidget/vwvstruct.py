
"""
GUI widgets for use in vstruct enabled applications
"""

import gtk
import inspect
import vstruct
import vstruct.primitives as vs_prims

import vwidget.main as vw_main
import vwidget.util as vw_util
import vwidget.views as vw_views

target_entries = [('example', gtk.TARGET_SAME_APP, 0)]

class VStructView(vw_views.VTreeView):
    __model_class__ = gtk.TreeStore
    __cols__ = (
        (None, 0, object),
        #FIXME offset and use vsGetPrintInfo
        ("Offset", 1, str),
        ("Name", 2, str),
        ("Type", 3, str),
    )

    def __init__(self, vs, editable=False):
        self.mystruct = vs
        vw_views.VTreeView.__init__(self)

        if editable:
            self.treeview.enable_model_drag_dest(target_entries, gtk.gdk.ACTION_MOVE)
            self.treeview.connect('drag-data-received', self.vwDragRecv)

    def vwDragRecv(self, treeview, dcontext, x, y, sdata, info, etime):
        print "DROP!",sdata.data
        drow = treeview.get_dest_row_at_pos(x, y)
        print repr(self.treeview),repr(treeview)
        if drow == None:
            titer = None
            dpos = gtk.TREE_VIEW_DROP_AFTER
        else:
            tpath, dpos = drow
            titer = self.model.get_iter(tpath)

        #if dpos == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE:
            #new = self.model.prepend(parent=target, row=source_row)
        #elif dpos == gtk.TREE_VIEW_DROP_INTO_OR_AFTER:
            #new = self.model.append(parent=target, row=source_row)
        #elif dpos == gtk.TREE_VIEW_DROP_BEFORE:
            #new = self.model.insert_before(parent=None, sibling=target, row=source_row)
        #elif dpos == gtk.TREE_VIEW_DROP_AFTER:
            #new = self.model.insert_after(parent=None, sibling=target, row=source_row)

        dcontext.finish(success=False, del_=False, time=etime)

    def bumpOffsets(self):
        #FIXME on proto change, field must be bumped
        pass

    def vwLoad(self):
        self.model.clear()
        i = self.model.append(None, (self.mystruct, "00000000", self.mystruct._vs_name, ""))
        todo = [(self.mystruct, i, 0),]
        while len(todo):
            d,iter,baseoff = todo.pop()
            for name,field in d: # FIXME unify iter for vstruct w/o name?
                if isinstance(field, vstruct.VStruct):
                    off = d.vsGetOffset(name)
                    i = self.model.append(iter, (d, "%.8x" % (baseoff+off), name, ""))
                    todo.append((field, i, baseoff+off))

                elif isinstance(field, vstruct.VArray):
                    pass

                else:
                    off = d.vsGetOffset(name)
                    self.model.append(iter, (field, "%.8x" % (baseoff+off), name, field.vsGetTypeName()))

    def vwActivated(self, tree, path, column):
        print "WOOT"
        pass

class VStructBrowser(vw_views.VTreeView):
    __model_class__ = gtk.TreeStore
    __cols__ = (
        (None, 0, object),
        ("Name", 1, str),
    )

    def __init__(self):
        vw_views.VTreeView.__init__(self)
        self.treeview.enable_model_drag_source(
            gtk.gdk.BUTTON1_MASK,
            target_entries,
            gtk.gdk.ACTION_MOVE)
        self.treeview.connect("drag-data-get", self.vwDragGet)

    def vwDragGet(self, treeview, dcontext, sdata, info, etime):
        treesel = treeview.get_selection()
        model, iter = treesel.get_selected()
        text = model.get_value(iter, 1)
        sdata.set('example', 8, text)
        return

    def vwLoad(self):
        self.model.clear()
        # Start with just the primitives.
        piter = self.model.append(None, (vs_prims, "primitives"))
        for name in dir(vs_prims):
            c = getattr(vs_prims, name)

            if inspect.isclass(c):

                if issubclass(c, vs_prims.v_prim):
                    self.model.append(piter, (c, c.__name__))

class VStructAttrs(vw_views.VTreeView):
    pass

