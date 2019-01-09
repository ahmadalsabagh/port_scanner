import socket
import getopt
import sys
import threading
import time

#semaphore used for controling threading output
printLock = threading.Semaphore(value=1)

def usage():
    print('[-] TCP Connect Port Scanner')
    print('[-] Usage: ' + sys.argv[0] + ' -H <hostname> -p [<target port(s)> comma seperated]')

#takes input from cmd line and passes it to portScan function
def main():
    if not len(sys.argv[4:]):
        usage()
        exit(1)
    try:
        opts,args = getopt.getopt(sys.argv[1:],"H:p:")
        #print(opts[1][1])
        portScan(opts[0][1],opts[1][1])
    except getopt.GetoptError as e:
        print("[-] Error: " + str(e))
        usage()
        

#outputs attempt to connect to host
def connScan(host,port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host,int(port)))
        printLock.acquire()
        print('[+] %d/tcp open') % int(port)
        sock.close()
    except:
        printLock.acquire()
        print('[-] %d/tcp closed') % int(port)
    finally:
        printLock.release()
        sock.close()


#attempts to resolve IP address, prints hostname/ip and enumerates through
#each individual port attempting to connect using the connScan function
def portScan(host,ports):
    
    #parse ports first
    ports = ports.replace("[","")
    ports = ports.replace("]","")
    ports = ports.split(",")

    try:
        IPaddr = socket.gethostbyname(host)
        print('DNS Lookup: ' + IPaddr)
    except:
        print('[-] Cannot resolve %s: Unknown host' % host)
        return

    try:
        tgtName = socket.gethostbyaddr(IPaddr)
        print('[+] Scan results for: ' + tgtName[0])
    except:
        print('[+] Scan results for: ' + IPaddr)
    socket.setdefaulttimeout(1)

    for tgtPort in ports:
        #concurrent scanning
        t = threading.Thread(target=connScan, args=(host,int(tgtPort)))
        t.start()

main()
