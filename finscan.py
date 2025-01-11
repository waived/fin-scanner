import sys, os, socket, threading, time
from scapy.all import *
from urllib.parse import urlparse

_ports = []
_alive = 0

def _scan(_ip, _prt, _wait, _time, abort_event):
    global _ports, _alive
    
    _alive +=1
    try:
        # craft fin packet
        response = sr1(IP(dst=_ip)/TCP(dport=int(_prt), flags="F"), timeout=int(_time), verbose=0) #flags=FPUSRAEC
        
        # check response
        if response is None:
            # fin packet succeeded. no response expected
            print(f"[{_ip}:{_prt}]\t Open!")
        
        # if a response was captured
        else:
            if response.haslayer(TCP):
                # rst/ack captured
                if response[TCP].flags == 0x04: #x14=Rst/Ack
                    print(f"[{_ip}:{_prt}]\t Closed")
                    _ports.remove(int(_prt))
            else:
                print(f"[{_ip}:{_prt}]\t Closed/filtered")
                _ports.remove(int(_prt))
            
    except:
        print(f"[{_ip}:{_prt}]\t Closed/filtered")
        _ports.remove(int(_prt))
        
    # sleep for x amount of milliseconds
    start_time = time.perf_counter()
    while (time.perf_counter() - start_time) * 1000 < int(_wait):
        if abort_event.is_set():
            break
    
    _alive -=1
    
    
def _rslv(_host):
    # format entry as uri class. works for both IP addresses and hostnames
    if not (_host.lower().startswith('http://') or _host.lower().startswith('https://')):
        _host = 'http://' + _host
    
    # extract domain from url + dns resolution
    try:
        _domain = urlparse(_host).netloc
        _ip = socket.gethostbyname(_domain)
        return _ip
    except:
        sys.exit('\r\nDNS resolution error! Exiting...\r\n')

def main():
    # confirm script elevation
    if not os.getegid() == 0:
        sys.exit('\r\nScript requires root elevation!\r\n')
    
    global _ports, _alive
    os.system('clear')
    print(r'''
                             __     _
                        _wr""        "-q__
                     _dP                 9m_
                   _#P                     9#_
                  d#@                       9#m
                 d##                         ###
                J###                         ###L
                {###K                       J###K
                ]####K      ___aaa___      J####F
            __gmM######_  w#P""   ""9#m  _d#####Mmw__
         _g##############mZ_         __g##############m_
       _d####M@PPPP@@M#######Mmp gm#########@@PPP9@M####m_
      a###""          ,Z"#####@" '######"\g          ""M##m
     J#@"             0L  "*##     ##@"  J#              *#K
     #"               `#    "_gmwgm_~    dF               `#_
    7F                 "#_   ]#####F   _dK                 JE
    ]                    *m__ ##### __g@"                   F
    \                      "PJ#####LP"                      /
     `                       0######_                      '
                           _0########_
         .               _d#####^#####m__              ,
          "*w_________am#####P"   ~9#####mw_________w*"
              ""9@#####@M""           ""P@#####@M""
    ''') 

    # capture user input
    try:
        # resolve hostname
        _host = input('Enter IP/site to scan: ')
        _ip = _rslv(_host)
        
        print('\r\nEnter in port(s) to scan. Can be a single port')
        print('or from a range of ports, ex: "1-1024". Enter "exit"')
        print('when finished.\r\n')
        
        _done = False
        while _done != True:
            _prt = input('Port/range> ')
            
            if _prt == 'exit':
                _done = True
            elif '-' in _prt:
                # add range to list
                try:
                    _min, _max = _prt.split('-')
                    if int(_min) > int(_max):
                        _min = _max
                    
                    # add range to list
                    for _ in range(int(_min), int(_max)):
                        _ports.append(_)
                except:
                    pass
            else:
                # add single port to list
                _ports.append(int(_prt))
        
        if len(_ports) == 0:
            # ensure an empty list is not scanned
            sys.exit('At least one port must be specified! Exiting...\r\n')
            
        _thdz = input('\r\n# of threads (default=5): ')
        _time = input('Timeout sec (default=1): ')
        _wait = input('Sleep in M/s (default=100): ')
        
        input('\r\nReady? Strike <ENTER> to launch and <CTRL+C> to abort...')
        
        print('\r\nScanning! Please stand-by\r\n')
        
        # remove list duplicates / order ports from lst to grtst
        _ports = list(set(_ports))
        _ports = sorted(_ports)
    except KeyboardInterrupt:
        sys.exit('\r\nAborted!\r\n')

    # manage thread/scan execution
    abort_event = threading.Event()
    try:    
        for _prt in _ports:
            while True:
                if _alive != int(_thdz):
                    x = threading.Thread(target=_scan, args=(_ip, _prt, _wait, _time, abort_event))
                    x.daemon = True
                    x.start()
                    break
    except KeyboardInterrupt:
        abort_event.set()
        
    # wait till threads power off
    while True:
        if _alive == 0:
            break
    
    # dump alive ports to .txt
    try:
        chs = input('\r\nDump valid ports to textfile? Y/n: ')
        if (chs.lower() == 'y' or chs.lower() == 'yes'):
            with open('ports.txt', 'w') as file:
                for item in _ports:
                    file.write(str(item) + '\n')
            file.close()
            print('\r\nDumped to file "ports.txt"\r\n')
    except KeyboardInterrupt:
        pass
    except:
        pass    
    
    sys.exit("\r\n\r\nStill rollin' out the hitz!")

if __name__ == '__main__':
    main()
