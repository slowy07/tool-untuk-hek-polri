#! /usr/bin/python
import time,sys,socket,colorama,threading,requests,argparse,os
from colorama import Fore
from os import system,name

wl=''
StatusWl=''

tgl = time.strftime("%m/%d/%Y",time.localtime())
waktu = time.strftime("%H:%M:%S",time.localtime())

def banner():
	if name == "nt":
		system("cls")
	else:
		system("clear")
	
	print(Fore.WHITE+'''
 _____  _      __   __        _         _  _   
|  _  \(_)     \ \ / /       | |       (_)| |  
| | | | _  _ __ \ V /  _ __  | |  ___   _ | |_ 
| | | || || '__|/   \ | '_ \ | | / _ \ | || __|
| |/ / | || |  / /^\ \| |_) || || (_) || || |_ 
|___/  |_||_|  \/   \/| .__/ |_| \___/ |_| \__|
                      | |                      
                      |_|       

[@] Author : FierzaXploit
[~] Instagram : zero.byte.forum
[~] Github : fierzaeriez.github.io
[~] Version : 1.0.0 (Release)
		''')

parser = argparse.ArgumentParser(banner())
parser.add_argument('-u','--url',help='Website/Target',dest='host',required=True)
parser.add_argument('-wl','--wordlist',action=argparse.BooleanOptionalAction,help='Change Wordlist',dest='wordlist')
parser.add_argument('-to','--timeout',type=int,help="Set Timeout",default=5,dest='limit')
arg = parser.parse_args()

if sys.version_info < (3, 0):
	sys.stdout.write(f"Sorry, DirXploit requires Python 3.x\n")
	sys.exit(1)

host = arg.host
wordlist = arg.wordlist
limit = arg.limit

try:
	print (Fore.WHITE+f'[^] [{tgl}][{waktu}] Checking HOST... '),
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		status = s.connect_ex((host, 80))
		s.close()
		if status == 0:
			print(f'[^] [{tgl}][{waktu}] {host} Is Ready')
			pass
		else:
			print (f'[!] [{tgl}][{waktu}] {host} FAIL')
			print (f'[!] [{tgl}][{waktu}] Error: Cannot Reach HOST %s\n' %(host))
			sys.exit(1)
	except socket.error:
		print (f'[!] [{tgl}][{waktu}] {host} FAIL')
		print (f'[!] [{tgl}][{waktu}] Error: Cannot Reach HOST: %s\n' %(host))
		sys.exit(1)

	if wordlist == True:
		wl = input('[$] PATH Wordlist : ')
		StatusWl = ''
	else:
		wl = 'db/dicc.txt'
		StatusWl = '[ Default Wordlist ]'
		print (f'\n[^] [{tgl}][{waktu}] Parsing Wordlist... '),

	try:
		with open(wl) as file:
			to_check = file.read().strip().split('\n')
		print(f'[^] [{tgl}][{waktu}] Path Wordlist : {wl} '+StatusWl)
		print (f'[^] [{tgl}][{waktu}] Wordlist Is Ready...')
		print (f'[^] [{tgl}][{waktu}] Total Paths to Check: %s' %(str(len(to_check))))
	except IOError:
		print (f'[!] [{tgl}][{waktu}] Wordlist Fail To Load')
		print (f'[!] [{tgl}][{waktu}] Error: Failed to Read Specified File\n')
		sys.exit(1)
	
	def checkpath(path):
		global response 
		response =''
		try:
			response = requests.get(
				'http://' + host + '/' + path,
				timeout=limit,
				headers={
					'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
					'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36',
					'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12',
					'User-Agent': 'Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) GSA/6.0.51363 Mobile/12H321 Safari/600.1.4',
					'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:28.0) Gecko/20100101 Firefox/28.0',
				},
			).status_code
		except Exception as err:
			pass
		
		if response == 200:
			print (Fore.LIGHTGREEN_EX+f'[*] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 200 ok ] => '+host+'/'+path)
		elif response == 301:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 301 Moved Permanently ]')
		elif response == 302:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 302 Moved temporarily ]')
		elif response == 303:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 303 See other location ]')
		elif response == 304:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 304 Not modified ]')
		elif response == 305:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 305 Use proxy ]')
		elif response == 307:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 307 Temporary redirect  ]')
		elif response == 308:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 308 Permanent Redirect ]')
		elif response == 400:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 400 Bad Request ]')
		elif response == 401:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 401 Unauthorized ]')
		elif response == 403:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 403 Forbidden ]')
		elif response == 404:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 404 Not Found ]')
		elif response == 405:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 405 Method not allowed ]')
		elif response == 406:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 406 Not Acceptable ]')
		elif response == 408:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 408 Request Timeout ]')
		elif response == 500:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 500 Internal Server Error ]')
		elif response == 501:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 501 Not Implemented ]')
		elif response == 502:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 502 Bad Gateway  ]')
		elif response == 503:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 503 Service Unavailable ]')
		elif response == 504:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 504 Gateway timeout ]')
		elif response == 505:
			print (Fore.LIGHTRED_EX+f'[\] [{tgl}][{waktu}] Path : %s' %(path),' [ HTTP 505 HTTP version not supported ]')
		else:
			print (Fore.LIGHTRED_EX+f'[x] [{tgl}][{waktu}] {host} Is Down...')

	def main(to_check):
		print (f'\n[^] [{tgl}][{waktu}] {host} Beginning Scan...')
		for i in range(0,len(to_check)):
			checkpath(to_check[i])
		print (Fore.GREEN+f'\n[*] [{tgl}][{waktu}] Scan Complete!...')

except KeyboardInterrupt:
	print (Fore.RED+'\n[!] Error: User Interrupted Scan')
	sys.exit(1)


if __name__ == "__main__":
	fast = threading.Thread(target=main,args=(to_check,))
	fast.start()> 