import struct, sys, time, Queue, threading
from Buffer import *
from IdaInterface import *
from socket import socket
from socket import timeout
from threading import Thread

def test():
    dbg = IDebug()
    dlistener = Dlistener(dbg)
    dlistener.start_listener()
    return dlistener

def generic_consend_test(server, port):
    s = socket()
    data = Buffer("hello world")
    s.connect((server, port))
    data.make_buffer_sendable()
    s.send(data.get_buf())
    s.close()

def generic_interact_test(server, port):
    s = socket()
    data = Buffer("hello there\n")
    data.make_buffer_sendable()
    print hex(len(data.get_buf())), hex(data.read_int()),data.get_buf()
    s.connect((server, port))
    s.send(data.get_buf())
    data.reset()
    data.append("Do you have and Grey Poupon?\n")
    data.make_buffer_sendable()
    print hex(len(data.get_buf())), hex(data.read_int()),data.get_buf()
    s.send(data.get_buf())
    buf = s.recv(65535)
    print buf
    bufs = input("Enter a response")
    s.send(bufs)
    s.close()    
    


# TODO Test Buffer, RecvThread, and ServerThread classes
# concurrency issues, reading and writing, etc.


class VtraceDebugger:
    def __init__(self, vtrace):
        self.vtrace = vtrace
    
    
        
    



class RecvThread(threading.Thread):
    def __init__(self, cmd_class):
        threading.Thread.__init__(self)
        self.queue = cmd_class.recvQ
        self.cmd_class = cmd_class
        self.handle_queue = True
        self.ev = threading.Event()
        self.msg_builder = MsgBuilder()
    
    def notify(self):
        self.ev.set()
    
    def stop(self):
        self.handle_queue = False
        self.ev.set()
    
    def run(self):
        while self.handle_queue:
            if self.queue.empty():
                self.ev.wait(.1)
                if self.ev.is_set():
                    self.ev.clear()
                continue
            # process data as buffer
            data_buf = self.queue.get()
            cmd = MsgBuilder.parse_message(data_buf)
            print cmd
            if cmd and cmd == "req":
                self.cmd_class.handle_remote_request(cmd)
            elif cmd and cmd == "rsp":
                self.cmd_class.handle_remote_request(cmd)
            else:
                self.cmd_class.garbage_pail(cmd)
    


class ServerThread(threading.Thread):
    def __init__(self, cmd_class, address="127.0.0.1", port=8088):
        threading.Thread.__init__(self)
        self.server = (address, port)
        self.client = None
        self.cmd_class = cmd_class
        self.listen = False
        self.sock = socket()
        self.sock.settimeout(2)
        self.sock.bind(self.server)
        self.client = None
        self.connected = False
        self.conn_lock = threading.Lock()
        # for the time being, maintain a msg parser that
        # will build the messages to send out
        self.msg_builder = MsgBuilder()
    
    def run(self):
        self.listen = True
        self.sock.listen(1)
        self.client = None
        while self.listen:
            try:
                client, addr = self.sock.accept()
                self.accept_conn(client)
                self.recv_traffic()
            except timeout:
                pass
            except:
                print "Client Error :("
                print "Experiened an exception: %s"%(str(sys.exc_info()[1]))
                print "Experiened an exception type: %s"%(str(sys.exc_info()[0]))
                self.shutdown_conn()
    
    def is_connected(self):
        return self.connected
        
    def shutdown_conn(self):
        self.conn_lock.acquire()
        try:
            self.client.close()
        except:
            pass
        self.client = None
        self.connected = False
        self.conn_lock.release()
    
    def accept_conn(self, client):
        self.conn_lock.acquire()
        self.client = client
        self.connected = True
        self.conn_lock.release()
    
    def send_buffer(self, buffer):
        buffer.make_buffer_sendable()
        self.send_traffic(buffer)
    
    def send_traffic(self, data):
        self.conn_lock.acquire()
        if self.client and self.connected:
            try:
                self.client.send(data)
                self.conn_lock.release()
                return True
            except:
                self.conn_lock.release()
                self.shutdown_conn()
                print "Exception when trying to send data"
        print self.client
        print self.connected
        return False
        
    def recv_traffic(self):
        print "Receiving client: ",str(self.client.getpeername())
        current_length = 0
        data_buf = Buffer()
        while self.listen and self.client:
            try:
                self.conn_lock.acquire()
                #print "Looping...."
                # will read the initial packet
                if current_length > 0:
                    t = self.client.recv(current_length)
                    current_length -= len(t)
                    data_buf.append(t)
                elif current_length == 0:
                    # clear buffer and wait
                    # for new pkt
                    #print "Data buffer was reset, recv'ing a new buf"
                    data_buf.append(self.client.recv(4))
                    current_length = data_buf.read_int() - 4
                    print "Recieved the current length %x"%(current_length+4)
                if current_length == 0 and len(data_buf) > 0:
                    print "Handling the following pkt: %s"%(repr(data_buf.get_buf()))
                    self.handle_recv(data_buf)
                    data_buf = Buffer()
                self.conn_lock.release()
            except timeout:
                if self.conn_lock.locked():
                    self.conn_lock.release()
                print "Timeout occured on the client"
                pass
            except Exception, e:
                if self.conn_lock.locked():
                    self.conn_lock.release()
                if str(sys.exc_info()[1]).find("Errno 10035") > -1:
                    pass
                else:
                    print "Exception Type: %s"%(str(sys.exc_info()[0]))
                    print "Exception Message: %s"%(str(sys.exc_info()[1]))
                    raise e
        print "Fell out of the loop :("
    
    def handle_recv(self, data_buf):
        self.cmd_class.handle_recv(data_buf)
        
    def stop(self):
        self.listen = False
        try:
            self.shutdown_conn()
            self.sock.close()
        except:
            pass
        self.sock = None
    
class Dlistener:
    def __init__(self, dbg):
        self.server = ("127.0.0.1", 8088)
        self.server_thread = None
        self.recvQ = Queue.Queue()
        self.recv_thread = RecvThread(self)
        self.dbg = dbg
        self.dbgLock = threading.Lock()
        
    
    def handle_local_cmd(self, cmd_str):
        if not self.server_thread:
            print "Not listening for clients"
            return False
        elif not self.server_thread.is_connected():
            print "Not connected to any clients"
            return False
        # TODO process cmd str and create a buffer
        cmd_list = cmd_str.split()
        buffer = MsgBuilder.build_message(*cmd_list)
        buffer.make_buffer_sendable()
        return self.server_thread.send_traffic(buffer.get_buf())
    
    def handle_remote_request(self, data):
        # strict ordering on commands, no handling 
        # more than 1 command, make the processor wait ;)
        self.dbgLock.acquire()
        self.dbg.handle_request(data)
        self.dbgLock.release()
    
    def handle_remote_response(self, data):
        # strict ordering on commands, no handling 
        # more than 1 command, make the processor wait ;)
        self.dbgLock.acquire()
        self.dbg.handle_response(data)
        self.dbgLock.release()
    
    def garbage_pail(self, data):
        print "WTF mate !?!?!: %s"%(str(data))
    
    
    def handle_recv(self, data_buf):
        # add data to Queue
        self.recvQ.put(data_buf)
        self.recv_thread.notify()
        
    def handle_send(self, data):
        # dont really care about 
        # reliability atm
        pass
    
    def start_listener(self, server=None, port=None):
        self.recv_thread = RecvThread(self)
        self.recv_thread.start()
        if server and port:
            self.server = (server, port)
        server,port = self.server
        self.server_thread = ServerThread(self, server, port)
        self.server_thread.start()
    
    def stop_listener(self):
        self.server_thread.stop()
        self.recv_thread.stop()
        self.recvQ.queue.clear()
        

class IDebug:
    def __init__(self):
        pass
    def handle_response(self, data):
        print "Received the following response: %s"%(data)
        
    def handle_request(self, data):
        print "Received the following request: %s"%(data)
    

    

