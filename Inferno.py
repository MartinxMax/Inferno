#!/usr/bin/python3
# @Мартин.
# ███████╗              ██╗  ██╗    ██╗  ██╗     ██████╗    ██╗  ██╗     ██╗    ██████╗
# ██╔════╝              ██║  ██║    ██║  ██║    ██╔════╝    ██║ ██╔╝    ███║    ╚════██╗
# ███████╗    █████╗    ███████║    ███████║    ██║         █████╔╝     ╚██║     █████╔╝
# ╚════██║    ╚════╝    ██╔══██║    ╚════██║    ██║         ██╔═██╗      ██║     ╚═══██╗
# ███████║              ██║  ██║         ██║    ╚██████╗    ██║  ██╗     ██║    ██████╔╝
# ╚══════╝              ╚═╝  ╚═╝         ╚═╝     ╚═════╝    ╚═╝  ╚═╝     ╚═╝    ╚═════╝


import argparse
import textwrap
import sys
import subprocess
from cpppo.server.enip import client

logo = f'''
██╗    ███╗   ██╗    ███████╗    ███████╗    ██████╗     ███╗   ██╗     ██████╗
██║    ████╗  ██║    ██╔════╝    ██╔════╝    ██╔══██╗    ████╗  ██║    ██╔═══██╗
██║    ██╔██╗ ██║    █████╗      █████╗      ██████╔╝    ██╔██╗ ██║    ██║   ██║
██║    ██║╚██╗██║    ██╔══╝      ██╔══╝      ██╔══██╗    ██║╚██╗██║    ██║   ██║
██║    ██║ ╚████║    ██║         ███████╗    ██║  ██║    ██║ ╚████║    ╚██████╔╝
╚═╝    ╚═╝  ╚═══╝    ╚═╝         ╚══════╝    ╚═╝  ╚═╝    ╚═╝  ╚═══╝     ╚═════╝
                Github==>https://github.com/MartinxMax
                S-H4CK13@Мартин. Inferno'''

class H4ck13Core:
    def __init__(self, args):
        self.scan = args.SCAN
        self.rhost = args.RHOST
        self.rport = args.RPORT
        self.get_tag = args.GTAG
        self.tag = args.TAG.split(',')
        self.read = args.READ
        self.write = args.WRITE
        self.wordlist = []

        if self.scan:
            self.__scan_device()
        elif self.get_tag:
            self.__wordlist()
            for tag in self.wordlist:
                tag_1 = self.__tag_exists(tag)
                if tag_1:
                    len = self.__guess_tag_length(tag)
                    print(f"[+] {self.rhost} tag: {tag}[{len}]")
        elif self.tag:
            if self.read:
                for tag in self.tag:
                    print(f"[*] read to tag [{tag}]")
                    if '-' in self.read:
                        self.read= self.read.split('-')
                        for i in range(int(self.read[0]),int(self.read[1])+1):
                            self.__read(tag,i)
                    else:
                        self.__read(tag,self.read)
            elif self.write:
                for tag in self.tag:
                    print(f"[*] write to tag [{tag}]")
                    if '(' in self.write and ')' in self.write and ':' in self.write:
                        self.write= self.write.split(':')
                        # <Index>:(INT):<Value>
                        if '-' in self.write[0]:
                            indexs = self.write[0].split('-')
                            for i in range(int(indexs[0]),int(indexs[1])+1):
                                self.__write(tag,i,''.join(self.write[1]+self.write[-1]))
                        else:
                            self.__write(tag,self.write[0],''.join(self.write[1]+self.write[-1]))

    def __write(self,tag,index,value):
        with client.connector( host=self.rhost ) as conn:
            for index,descr,op,reply,status,rvalue in conn.pipeline(
                operations=client.parse_operations( [tag+f"[{index}]="+value] ), depth=2 ):
                print(f"[+] {descr} <<< {value}")

    def __read(self,tag,index):
        with client.connector( host=self.rhost ) as conn:
            for index,descr,op,reply,status,value in conn.pipeline(
                operations=client.parse_operations( [tag+f"[{index}]"] ), depth=2 ):
                print(f"[+] {descr} >>> {value}")


    def __scan_device(self):
        print(f"[*] Scanning IP: {self.scan}")
        result = subprocess.run(['nmap', '-p', '44818', '--open', '-T4', '--min-parallelism', '100', '--max-parallelism', '256', '-oG', '-', self.scan], capture_output=True, text=True)
        hosts = [line.split()[1] for line in result.stdout.split('\n') if 'Ports: 44818/open' in line]
        for host in hosts:
            result = subprocess.run(['nmap', '-p', '44818', '--script=enip-info', '-T4', '--min-parallelism', '100', '--max-parallelism', '256', host], capture_output=True, text=True)
            if '44818/tcp open  EtherNet-IP-2' in result.stdout:
                print(f"[+] {host} has EtherNet/IP")

    def __wordlist(self):
            try:
                with open('./Wordlist.txt', 'r') as file:
                    self.wordlist = file.read().splitlines()
            except FileNotFoundError:
                print(f"[!] File Wordlist.txt not found.")
            except Exception as e:
                print(f"[!] An error occurred while reading the file Wordlist.txt: {e}")


    def __tag_exists(self, tag):
        try:
            with client.connector(host=self.rhost) as conn:
                _, _, _, _, _, value = next(conn.pipeline(
                    operations=client.parse_operations([tag+"[0]"]), depth=1))
                return value is not None
        except Exception as e:
            return False

    def __guess_tag_length(self, tag):
        with client.connector(host=self.rhost) as conn:
            last_length_guess = 0
            for length_guess in range(1, 65536):
                guessed_tag = f"{tag}[{length_guess}]"
                _, _, _, _, _, value = next(conn.pipeline(
                    operations=client.parse_operations([guessed_tag]), depth=2))
                if value is None:
                    break
                else:
                    last_length_guess = length_guess
            return last_length_guess+1

if __name__ == '__main__':
    print(logo)
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
epilog=textwrap.dedent('''
    Example:
        author-Github==>https://github.com/MartinxMax
    Basic usage:
        python3 {Inf} -scan <192.168.8.0/24> # Scan EtherNet/IP devices
        python3 {Inf} -rhost <192.168.8.105> -gtag # Get tags
        python3 {Inf} -rhost <192.168.8.105> -tag <SCADA> -read 1 # Read Tag[SCADA] index 1
        python3 {Inf} -rhost <192.168.8.105> -tag <SCADA> -read 1-10 # Read Tag[SCADA] index 1-10
        python3 {Inf} -rhost <192.168.8.105> -tag <SCADA> -write 1:(INT):22 # Write Tag[SCADA] index 1 to value 22
        python3 {Inf} -rhost <192.168.8.105> -tag <SCADA> -write 1-10:(INT):22 # Write Tag[SCADA] index 1-10 to value 22

                       '''.format(Inf=sys.argv[0]))
            )

    parser.add_argument('-scan', '--SCAN', default='', help='IP range to scan')
    parser.add_argument('-rhost', '--RHOST', default='', help='Host ip')
    parser.add_argument('-rport', '--RPORT', default='44818', help='Host port')
    parser.add_argument('-gtag', '--GTAG',  action='store_true', help='Get tags')
    parser.add_argument('-tag', '--TAG', default='', help='Assignment tag')
    parser.add_argument('-read', '--READ', default='', help='Read data [index] or [index-index+1]')
    parser.add_argument('-write', '--WRITE', default='', help='Write data [index:(INT):value] or [index-index+1:(INT):value])')
    args = parser.parse_args()
    H4ck13Core(args)

