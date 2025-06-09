from pyfiglet import Figlet
from colorama import Fore, Style, init,Back
import threading
import socket
import hashlib
import requests
from google import genai

# Pyshell - A simple python shell for ethical hacking and pentesting

# function to genrate hashes ( sha256, sha512, md5, sha1)
def generate_hash(text:str, algorithm:str='md5',verbosity:str="y"): 
    algorithms = ['md5','sha1','sha256','sha512']
    if algorithm not in algorithms:
        print(Fore.RED + f"Algorithm invalid or doen't exist")        
        return
    print((Fore.RED)+f"beginning hashing for {text} using {algorithm} algorithm")
    match algorithm:
        case 'md5':
            hash = hashlib.md5(text.encode()).hexdigest()
        case 'sha1':
            hash = hashlib.sha1(text.encode()).hexdigest()
        case 'sha256':    
            hash = hashlib.sha256(text.encode()).hexdigest()
        case 'sha512':    
            hash = hashlib.sha512(text.encode()).hexdigest()            
    print(Fore.GREEN + f"Hash generated successfully")
    print(Fore.GREEN + f"text:{text} Hash:{hash} algorithm:{algorithm}")
# function to genrate hashes ( sha256, sha512, md5, sha1)
def crack_hash(hash:str, algorithm:str='md5',wordlist:str="",verbose:bool=False):
  
    def crack(algo:str,text:str):
        match algo:
            case 'md5':
                 return(hashlib.md5(word.strip().encode()).hexdigest())
            case 'sha1':
                return(hashlib.md5(word.strip().encode()).hexdigest())
            case 'sha256':
                return(hashlib.md5(word.strip().encode()).hexdigest())
            case 'sha512':
                return(hashlib.md5(word.strip().encode()).hexdigest())
    with open(wordlist, 'r') as f:
        for word in f:
            if verbose:
                print(Fore.RED + f"[*] Trying word: {word.strip()}")
            wordHash = crack(algo=algorithm,text=word.strip())
            if wordHash == hash:
                print(Fore.GREEN+"Hash cracked successfully")
                print(Fore.GREEN + f" {word.strip()}: ({hash[:11]}....)")
                return
# function to scan for available ports on target system. currently scans ports 1-100
def port_scan(target:str, port:int=0,verbose:bool=False):
     if port == 0:
         open_port= []   
         print(Fore.RED + f"[*] Beginning port scan  on {target}")
         for i in range(1,101):
             try:
                  if verbose:
                    print(Fore.RED + f"[*] Scanning port {i}")
                  con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  con.settimeout(0.5)
                  r = con.connect_ex((target, i))                
                  if r==0:
                    open_port.append(i)
                    print(Fore.GREEN + f"Port {i} is open")
                  con.close()
             except:
                 pass
         if len(open_port) == 0:
             print(Fore.RED + f"No open ports found on {target}")
             print(Fore.RED + "Exiting...")
         else:        
             print(Fore.GREEN + f"Found {len(open_port)} port(s) open")        

#function for directory bruteforcing
def directory_bruteforce(target:str, path_wordlist:str, verbose:bool=False):
    count = 0
    with open(path_wordlist, 'r') as f:
        for word in f:
            if verbose:
                print(Fore.RED + f"[*] Trying directory: {word.strip()}")
            res = requests.get(f"{target}/{word.strip()}")
            if res.status_code == 200:
                print(Fore.GREEN + f"Found directory: {target}/{word.strip()}")
                count+=1

    print(Fore.GREEN + f"Directory scan completed. Found {count} directories.")            

# scan entries in robots.xt file allowed and disallowed entries can also be filtered
def scan_robots(target:str, allowed:bool=False, disallowed:bool=False):
    res = requests.get(f"{target}/robots.txt")
    if res.status_code == 200:
        print(Fore.GREEN + f"robots.txt found at {target}/robots.txt")
        print(Fore.GREEN + "Contents:")
        text = res.text
        if allowed:
            for line in text.splitlines():
                if line.startswith("Allow:"):
                    print(Fore.GREEN + line.strip())
        elif disallowed:
            for line in text.splitlines():
                if line.startswith("Disallow:"):
                    print(Fore.RED + line.strip())
        else:
            print(text)
    else:
        print(Fore.RED + f"robots.txt not found at {target}/robots.txt")
# scan the cipher type using gemini AI        
def ai_decipher(text:str,apikey:str):
    # Placeholder for AI deciphering logic
    client = genai.Client(api_key=apikey)
    response = client.models.generate_content(
    model="gemini-2.0-flash", contents=f"""Detect the cipher used in the following text and return ONLY the cipher type. Do not provide explanations or additional output.

Text:
{text}

Return format:
<Cipher Type>
"""
    )
    print(Fore.GREEN+ f"AI> {response.text}")
    # print(Fore.RED + "AI deciphering is not implemented yet.")

    return

#Choice
def choose_option():
    init()
    text = Figlet()

    print(Fore.RED + text.renderText("PYSHELL"))
    print(Fore.RED + "\t -BY Pratham \n \t Github: https://github.com/PrAtHaM161602 \n \t Only to be used for ethical hacking and pentesting purposes")
    options = ["port scan", "directory bruteforce", "robots.txt scanner","ai based cipher detection","crack hashes","generate hash","exit"]
    print(Fore.RED + "Choose options: \n")
    i = 0

    for option in options:
        print(Fore.RED + f"  {i+1} {option}")
        i+=1

    choice  = int(input(Fore.RED + "Enter your choice: "))
    match choice:
        case 1:
            print(Fore.RED + "Option selected: port scan")
   
            target = input(Fore.RED + "Enter target IP: ")
            v = input(Fore.RED+"Enable verbosity? (y/N): ")
            verbose = True if v.lower() == 'y' else False
            port_scan(target=target,verbose= verbose)
        case 2:
            print(Fore.RED + "Option selected: directory bruteforce")
            target = input(Fore.RED + "Enter target URL: ")
            path = input(Fore.RED + "Enter path to wordlist: ")
            verbose = input(Fore.RED + "Enable verbosity? (y/N): ")
            if verbose.lower() == 'y':
                verbose = True
            else:
                verbose = False    
            directory_bruteforce(target=target,path_wordlist=path,verbose=verbose)    
        case 3:
            allowed = False
            disallowed = False
            print(Fore.RED + "Option selected: robots.txt scanner")
            target = input(Fore.RED + "Enter target URL: ")
            allowed = input(Fore.RED + "Show only allowed paths? (y/N): ")
            if allowed.lower() == 'y':
                 allowed = True
        
            disallowed = input(Fore.RED + "Show disallowed paths? (y/N): ")
            if disallowed.lower() == 'y':
                 disallowed = True
         
            scan_robots(target=target,allowed=allowed,disallowed=disallowed)
        case 4:
            apikey=input("Enter gemini api key: ")
            cipher = input("Cipher to decipher: ")
            ai_decipher(text=cipher,apikey=apikey)
        case 5:
            print(Fore.RED + "Option selected: crack hashes")
            text = input(Fore.RED + "Enter hash to crack: ")
            algo = input(Fore.RED + "Enter hashing algorithm (default=md5): ")
            path = input(Fore.RED + "Enter path to wordlist path: ")
            crack_hash(hash=text,algorithm=algo,wordlist=path)    
        case 6:
            print(Fore.RED + "Option selected: generate hash")
            text = input(Fore.RED+ "Enter text to hash: ")
            algo = input(Fore.RED + "Enter hashing algorithm (default=md5): ")
            verbose = input(Fore.RED + "Enable verbosity? (y/N): ")
            if verbose.lower() == 'y':
                verbose = True
            else:
                verbose = False    
            generate_hash(text=text,algorithm = algo,verbosity=verbose)
        case 7:
            print(Fore.RED + "Exiting...")
            exit(0)    
        case _:
            print(Fore.RED + "Invalid option selected. Enter a valid choice")        
            choose_option()    

if __name__ == "__main__":
    try:
        choose_option()
    except KeyboardInterrupt:
        print(Fore.RED + "Exiting...")
        exit(0)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")
        exit(1)            