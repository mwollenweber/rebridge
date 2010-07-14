import struct, sys, time, Queue, threading
from Buffer import *
from socket import socket
from socket import timeout
from threading import Thread
import vdb


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
        self.cmd_class.handle_msg(data_buf)
        
    def stop(self):
        self.listen = False
        self.shutdown_conn()
        self.sock.close()
        self.sock = None
    
class Vdbbridge(vdb.Vdb):
    def __init__(self):
        self.server = ("127.0.0.1", 8088)
        self.server_thread = None
        self.recvQ = Queue.Queue()
        self.dbg = self
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
    
    def handle_msg(self, buffer):
        #print buffer
        cmd_type = buffer.read_int()
        cmd_name = buffer.read_string()
        return str(self.execute_cmd(cmd_type, cmd_name, buffer))
        
    def handle_cli(self, cmd, args):
        return str(self.execute_cmd(CMD_CLI, cmd, args))
            
    
    def start_listener(self, server=None, port=None):
        if server and port:
            self.server = (server, port)
        server,port = self.server
        self.server_thread = ServerThread(self, server, port)
        self.server_thread.start()
    
    def stop_listener(self):
        self.server_thread.stop()

vdbbridge = Vdbbridge()