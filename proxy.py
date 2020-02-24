import socket
import tkinter as tk
from tkinter import *
import sys,_thread
import time
import ssl

#port number & buffer size
#CONSTANTS
global list
MAX_DATA = 4096 # 4k default buffer
DEFAULT_PORT = 8080
BACKLOG = 1000
blocked_sites = [line.rstrip('\n') for line in open('blocked.txt')] # loading

#blocked_sites.append("scratchpads.eu") ## http blocking
#blocked_sites.append("www.un.org") ## https example blocking

cache = {} # dict as a cache for http responces
timeData = {}










def main():


    try:
        _thread.start_new_thread(gui,())
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)# af_inet = ipv4, sock_stream = tcp
        print("$ Initialising socket...")
        my_socket.bind(('',DEFAULT_PORT))# all interfaces port : default_port
        print("$ Bind successful")
        my_socket.listen(BACKLOG)# will accept #|backlog| values until it wont accept new connections
        print("$ Server listening on port [ %d ]\n" % (DEFAULT_PORT))
        printBlocked()
    except Exception as e0:
        print("$ socket initiation failed")
        sys.exit(0)

    ## loop while waiting for new connections from browser

    while True:
        try:
            my_connection, my_address = my_socket.accept() # setting up connection, addr using socket
            data = my_connection.recv(MAX_DATA)
            bandwidth = len(data)
            starting_time = time.time()
            _thread.start_new_thread(proxy,(my_connection, data, my_address,starting_time,bandwidth))
            time.sleep(0.0001)
        except ConnectionResetError:
            pass
        except KeyboardInterrupt:
        #my_connection.close()
            my_socket.close()
            print("$ socket force closed")
            sys.exit(1)

    my_socket.close()
    return



def printBlocked():
    print("Blocked Sites @ Init:\n")
    for i in blocked_sites:
        print(i)
    print("\n")

def gui():

    def block_entry():
        e = block.get()
        if e not in blocked_sites:
            blocked_sites.append(e)
            list.insert(END,e)
            print(e + " has been blocked")
        else:
            print(e," has already been blocked")

    def unblock_entry():
        e = unblock.get()
        if e in blocked_sites:
            blocked_sites.remove(e)
            for i, listbox_entry in enumerate(list.get(0, END)):
                if listbox_entry == e:
                    list.delete(i)
            print(e," has been unblocked")
        else:
            print(e," is not blocked")


    gui = tk.Tk()
    gui.geometry("350x300")
    gui.title('Blocking System')


    block = Entry(gui)
    block.grid(row=0, column=0)
    unblock = Entry(gui)
    unblock.grid(row=1, column=0)

    block_button = Button(gui, text = "Block", command=block_entry)
    block_button.grid(row=0, column=1)
    block_button = Button(gui, text = "Un-block", command=unblock_entry)
    block_button.grid(row=1, column=1)

    list = Listbox(gui)
    list.grid(row=2, columnspan=2)
    list.config(width=50, height=50)

    for elem in blocked_sites:
        list.insert(END,elem)

    mainloop()




def proxy(my_connection, data, my_address,starting_time,bandwidth):

    if data is None:
        return

    https, web_srv, port, url,method = parse_req(data)

    if web_srv in blocked_sites:
        print("$ That host is restricted! (",web_srv,")")
        my_connection.close()
        return

    if method != "GET" and method != "CONNECT":
        my_connection.close()
        print("$ Invalid method :",method, " connection closed")
        return


    print("$ starting new thread for : ",url)

    t0 = time.time()
    cached_response = cache.get(url)
    if cached_response != None:
        my_connection.sendall(cached_response)
        t1 = time.time()
        print("$ Cache hit on url: ",url,"\n$ Request took: " + str(t1-t0) + " seconds with cache.\n $ Request took: " + str(timeData[url]) + " seconds previously")
        #my_connection.close()
        return


    else:
            if https == False:
                bw = proxy_srv_http(web_srv,port,my_connection,data,my_address,url,bandwidth)
            else:
                proxy_srv_https(web_srv,port,my_connection,my_address,url)


            end = time.time()
            if https == False:
                print("$ time elapsed : ",str(end-starting_time), " seconds\n")
                if(bw == None):
                    print("$ No bandwidth usage (retrieved from cache) \n")
                else:
                    print("$ total bandwidth : ",str(bw), " bytes")
            my_connection.close()
            return


def proxy_srv_http(web_srv, port, my_connection, data, my_address, url,bandwidth):


    t0 = time.time()

    print("$ sending HTTP request url:",url)
    my_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket2.connect((web_srv, port))
    my_socket2.settimeout(3)
    my_socket2.setblocking(0)

    my_socket2.send(data)
    b = len(data)
    my_socket2.settimeout(3)


    if url in cache:
        print("$ Found request in cache")
        t1 = time.time()
        print("$ Request took: " + str(t1-t0) + "s with cache.")

    else:
        http_reply = bytearray("",'utf-8')
        try:
            while True:
                rcv = my_socket2.recv(MAX_DATA)
                if (len(rcv) > 0):
                    my_connection.send(rcv)
                    http_reply.extend(rcv)
                else:
                    break
        except socket.error:
            #print("$ HTTP socket error:",str(socket.error))
            pass
        t1 = time.time()
        cache[url] = http_reply

        timeData[url] = t1-t0
        print("$ added to cache (URL) : ",url)
        my_socket2.close()
        #print("$ HTTP Request completed (URL): ",url)
        b += len(http_reply)
        return b
    print("$ HTTP Request completed (URL): ",url)
    my_socket2.close()
    #print("$ HTTP socket closed ")





def proxy_srv_https(web_srv,port,my_connection,my_address,url):


    print("$ sending HTTPS")
    try:
        my_socket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket2.connect((web_srv, port))
        reply = "HTTP/1.0 200 Connection established\r\nProxy-agent: Pyx\r\n\r\n"
        my_connection.sendall(reply.encode())

    except socket.error as err:
	       print(err)
	       return

    my_connection.setblocking(0)
    my_socket2.setblocking(0)

    while True:
        try:
            request = my_connection.recv(MAX_DATA)
            my_socket2.sendall(request)
        except socket.error as err:
            pass
        try:
            reply = my_socket2.recv(MAX_DATA)
            my_connection.sendall(reply)
        except socket.error as err:
            pass

    print("$ HTTPS request completed (URL) : ",url)


def get_host(line_data):
    host = ""
    for line in line_data:
        h = line.find("Host")
        if h != -1:
            host = line
            break
    return host


def get_websrv(host):
    web_srv = host.split(": ")[1]
    port_pos = web_srv.find(":")
    web_srv2 = ""
    i = 0
    if port_pos != -1:
        while i < port_pos:
            web_srv2 += web_srv[i]
            i += 1
    else:
        web_srv2 = web_srv
    return web_srv2


def parse_req(data):
    try:
        https = False
        print("")
        print("$ Decoding request")

        line_data = data.decode().split("\r\n")

        get = line_data[0].find("GET")
        method = line_data[0].split(' ')[0]
        if get == -1:
            https = True

        url_http = line_data[0].split(' ')[1]

        url = "https://" + url_http.split(':')[0] + "/"

        host = get_host(line_data)
        webserver = get_websrv(host)

        print("$ Method :",method)
        print("$ URL :", url_http)
        print("$ Webserver:",webserver)

        if https is True:
            port = 443
        else:
            port = 80
        if https:
            return https, webserver, port, url, method
        else:
            return https, webserver, port, url_http, method
    except Exception:
        #print("decode exception")
        pass
        return True, 0, 0, "", ""


















main()
