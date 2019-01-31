import shodan
from shodan.client import Shodan
from shodan.exception import APIError
import time

def header():
        print("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|")
        print("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|")
        print("|-|-|-|-|-|-|-|-|-|   IoT Scanner   |-|-|-|-|-|-|-|-|-|")
        print("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|")
        print("|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|\n")

def delay(numero):
        time.sleep(numero)

header()
ip = input("IP: ") #70.184.73.186

print("\n[+] Analizando o IP %s..." %(ip))
delay(1)
print("[+] Se conectando ao IP %s..." %(ip))
delay(1.5)
print("[+] Se concetando ao Shodan...")
delay(1)

SHODAN_API_KEY = "61TvA2dNwxNxmWziZxKzR5aO9tFD00Nj"
api = shodan.Shodan(SHODAN_API_KEY)

print("[+] Scanneando portas...")
delay(3)
print("[+] Buscando serviços...")
delay(2)

searchQuery = "ip:" + ip
products = []
versions = []

try:

        host = api.search(searchQuery) # 151.111.124.198 and 70.184.73.186
        
        if 'product' in host['matches']:
                for item in host['matches']:
                        time.sleep(1)
                        products.append(item['product'])
                        versions.append(item['version'])
        else:
                ipinfo = api.host(ip)
                for item in ipinfo['data']:
                        time.sleep(1)
                        products.append(item.get('product'))
                        versions.append(item.get('version'))

except shodan.APIError:
        print("Error")

print("[+] Versionando os serviços...")
delay(1)
print("[+] Buscando Exploits...")
delay(1)



for i in range(len(products)):

        if products[i] != None:
                
                exploitQuery = products[i]
                print("")
                print(exploitQuery)
                exploit = api.exploits.search(exploitQuery)
                time.sleep(1)
        
                if exploit['total'] != 0:
                        for vulns in exploit['matches']:
                                time.sleep(1)
                                print("\nDevice-Service: %s" % (exploitQuery))
                                print("Source: {}".format(vulns['source']))
                                print("CVE: {}".format(vulns['cve']))
                                print("Description: {}".format(vulns['description']))
