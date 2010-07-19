import struct, sys, time, Queue, threading
from buffer import *
from threading import Thread


#from socket import socket
import socket
from socket import timeout

class RecvThread(threading.Thread):
    def __init__(self, network_thread):
        threading.Thread.__init__(self)
        self.queue = network_thread.recvQ
        self.network_thread = network_thread
        self.handle_queue = True
        self.bridge_class = network_thread.bridge_class
        self.ev = threading.Event()
    
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
            self.bridge_class.handle_msg(data_buf)
            

class ServerThread(threading.Thread):
    def __init__(self, bridge_class, address="127.0.0.1", port=8088):
        threading.Thread.__init__(self)
        self.server = (address, port)
        self.client = None
        self.bridge_class = bridge_class
        self.listen = False
        self.sock = socket.socket()
        self.sock.settimeout(2)
        self.sock.bind(self.server)
        self.client = None
        self.connected = False
        self.conn_lock = threading.Lock()
        self.recvQ = Queue.Queue()
        self.recv_thread = None #RecvThread(self)

    
    def run(self):
        self.listen = True
        self.sock.listen(1)
        self.client = None
        self.recv_thread = RecvThread(self)
        self.recv_thread.start()
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
    
    def send_buffer(self, buffer):
        buffer.make_buffer_sendable()
        return self.send_traffic(buffer.get_buf())

    def accept_conn(self, client):
        self.conn_lock.acquire()
        self.client = client
        self.client.settimeout(2)
        self.connected = True
        self.conn_lock.release()
    
    def send_traffic(self, data):
        self.conn_lock.acquire()
        #print "Sending the following data: %s"%(repr(data))
        if self.client and self.connected:
            try:
                self.client.send(data)
                self.conn_lock.release()
                return True
            except:
                self.conn_lock.release()
                self.shutdown_conn()
                print "Exception when trying to send data"
        #print self.client
        #print self.connected
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
                    #print "Handling the following pkt: %s"%(repr(data_buf.get_buf()))
                    self.handle_recv(data_buf)
                    data_buf = Buffer()
                self.conn_lock.release()
            except timeout:
                if self.conn_lock.locked():
                    self.conn_lock.release()
                #print "Timeout occured on the client"
                
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
        #print "Recv'd the following buffer: %s"%(repr(data_buf.get_buf()))
        #self.bridge_class.handle_msg(data_buf)
        self.recvQ.put(data_buf)
        self.recv_thread.notify()
        
    def stop(self):
        self.listen = False
        self.shutdown_conn()
        if self.recv_thread:
            self.recv_thread.stop()
            self.recv_thread = None
            self.recvQ.queue.clear()
        try:
            self.sock.close()
        except:
            pass
        self.sock = None

        
class ClientThread(threading.Thread):
    def __init__(self, bridge_class, address="127.0.0.1", port=8088):
        threading.Thread.__init__(self)
        self.server = (address, port)
        self.client = None
        self.bridge_class = bridge_class
        self.connected = False
        self.conn_lock = threading.Lock()
        self.recvQ = Queue.Queue()
        self.recv_thread = None #RecvThread(self)

    def run(self):
        self.recv_thread = RecvThread(self)
        self.recv_thread.start()
        self.client = socket.socket()
        self.client.settimeout(2)
        self.client.connect(self.server)
        self.connected = True
        while self.connected:
            try:
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
        
    def send_buffer(self, buffer):
        buffer.make_buffer_sendable()
        return self.send_traffic(buffer.get_buf())

    def shutdown_conn(self):
        self.conn_lock.acquire()
        try:
            self.client.close()
        except:
            pass
        self.client = None
        self.connected = False
        self.conn_lock.release()
        
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
        #print "Recv'd the following buffer: %s"%(repr(data_buf.get_buf()))
        #self.bridge_class.handle_msg(data_buf)
        self.recvQ.put(data_buf)
        self.recv_thread.notify()

        
    def stop(self):
        self.shutdown_conn()
        if self.recv_thread:
            self.recv_thread.stop()
            self.recv_thread = None
            self.recvQ.queue.clear()
        
# ida remote server ;)
class IDARS:
    def __init__(self):
        self.server = ("127.0.0.1", 8088)
        self.server_thread = None
        self.dbg = self
        self.dbgLock = threading.Lock()
                
    def start_listener(self, server=None, port=None):
        if server and port:
            self.server = (server, port)
        server,port = self.server
        self.server_thread = ServerThread(self, server, port)
        self.server_thread.start()
    
    def stop_listener(self):
        if self.server_thread:
            self.server_thread.stop()
        self.server_thread = None
    
    def is_connected(self):
        return not self.server_thread is None and\
                self.server_thread.is_connected()
    
    def send(self, buffer):
        self.server_thread.send_buffer(buffer)
    
    def handle_msg(self, buffer):
        # to be implemented by a bridge
        return ""
    
class IDAC:
    def __init__(self):
        self.server = ("127.0.0.1", 8088)
        self.client_thread = None
        self.dbg = self
        self.dbgLock = threading.Lock()
                
    def start(self, server=None, port=None):
        if server and port:
            self.server = (server, port)
        server,port = self.server
        self.client_thread = ClientThread(self, server, port)
        self.client_thread.start()
    
    def stop(self):
        if self.client_thread:
            self.client_thread.stop()
        self.client_thread = None
        
    def send(self, buffer):
        self.client_thread.send_buffer(buffer)
        
    def handle_msg(self, buffer):
        # to be implemented by a bridge
        return ""
    def is_connected(self):
        return not self.client_thread is None and\
                self.client_thread.is_connected()
