import requests
import random
import string
import json
import time
import os 
import subprocess,re
import sys
import gzip
import zlib
import zstandard as zstd
from user_agent import generate_user_agent
from colorama import Fore

useragents =  str(generate_user_agent)

session = requests.Session()

Setpassword = 'ASDF12345#'



def generate_random_username(length=10):
    characters = string.ascii_letters
    username = ''.join(random.choice(characters) for _ in range(length))
    return username


  




# GET COOKIES FOR INSTAGRAM

def header_cookie():
    csrftoken = ""
    ig_did = ""
    mid = ""
    
    response = session.post("https://www.instagram.com/accounts/signup/email/")
    cookies = response.cookies.get_dict()
    
    first_key, first_value = next(iter(cookies.items()))
    extracted_value = cookies[first_key]
    cookies = {
        first_key: extracted_value
    }
    
    response = requests.post('https://www.instagram.com/api/v1/web/login_page/', cookies=cookies)
    for cookie in response.cookies:
        if cookie.name == 'csrftoken':
            csrftoken = cookie.value
        elif cookie.name == 'ig_did':
            ig_did = cookie.value
        elif cookie.name == 'mid':
            mid = cookie.value
    
    return csrftoken, ig_did, mid






def get_email():
    url  = 'https://api.internal.temp-mail.io/api/v3/email/new'

    headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'en-US,en;q=0.9',
    'Application-Name': 'web',
    'Application-Version': '2.4.1',
    'Cache-Control': 'no-cache',
    'Content-Length': '43',
    'Content-Type': 'application/json;charset=UTF-8',
    'Origin': 'https://temp-mail.io',
    'Cookie':'_ga=GA1.2.1239562635.1719424024; _gid=GA1.2.1366826056.1721820067; __gads=ID=386ef560517c8945:T=1719424034:RT=1721820071:S=ALNI_MaLrf_1VHq04VCqkSr2dgbqf78Pqg; __gpi=UID=00000e658247d18f:T=1719424034:RT=1721820071:S=ALNI_Mawaem49vDlqhqCRECEXEmfj4KmZA; __eoi=ID=0adeef503080bd61:T=1719424034:RT=1721820071:S=AA-AfjYAqbOVbHeEDsREkcrHbQUu; FCNEC=%5B%5B%22AKsRol_J-H5nWdvVxL51a9KkjFJOw2czENkErIryGhbST9bR-nEIV2-DzsYFx0Zf9CDJFatnf5bLl__phohrbaOWqg0-3RqmufQzWJUvnN7x-9CEwhRH8O62it_mRYeXvapT7PeiYdvLzqReLxH8lKsUFZKODmWQMA%3D%3D%22%5D%5D; _gat=1; _ga_3DVKZSPS3D=GS1.2.1721820068.8.1.1721820564.60.0.0',
    'Pragma': 'no-cache',
    'Priority': 'u=1, i',
    'Referer': 'https://temp-mail.io/',
    'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    'Sec-Ch-Ua-Mobile': '?1',
    'Sec-Ch-Ua-Platform': '"Android"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'User-Agent': useragents
}

    data = {"min_name_length":10,"max_name_length":10}

    response = requests.post(url,json=data,headers=headers)
    text_res = json.loads(response.text)
    email = text_res.get('email')
    print(Fore.RED+'Done step 1')
    print(email)
    
    
    response = session.get("https://instagram.com")
    cookies = response.cookies
    csrftoken = cookies.get('csrftoken')
    return email,cookies




def decoder(response):


    # Check the content encoding type
    content_encoding = response.headers.get('Content-Encoding')
    try:
        if content_encoding == 'gzip':
            decoded_content = gzip.decompress(response.content).decode('utf-8')
        elif content_encoding == 'deflate':
            decoded_content = zlib.decompress(response.content, -zlib.MAX_WBITS).decode('utf-8')
        elif content_encoding == 'zstd':
            dctx = zstd.ZstdDecompressor()
            decoded_content = dctx.decompress(response.content).decode('utf-8')
        else:
            decoded_content = response.text

        print(decoded_content)
        return decoded_content

    except zstd.ZstdError as e:
        print(f"ZstdError: {e}")
        print(f"Content (truncated): {response.content[:100]}")
    except (gzip.BadGzipFile, zlib.error) as e:
        print(f"DecompressionError: {e}")
        print(f"Content (truncated): {response.content[:100]}")
    except UnicodeDecodeError as e:
        print(f"UnicodeDecodeError: {e}")
        print(f"Decoded content (truncated): {decoded_content[:100]}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        print(f"Content (truncated): {response.content[:100]}")



def imp_info(username,csrftoken, ig_did, mid,email,cookies):
    url = 'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/'




    timestamp = str(time.time()).split('.')[0]

    data = {
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{Setpassword}',
        'email': str(email),
        'first_name': username,
        'username': username,
        'client_id': '1j60p0c19iywxspfimwt1ezse3iy7yrkanwza0hcknxhgj90oxr',
        'seamless_login_enabled': 1,
        'opt_into_one_tap': 'false'


    }
#    

    headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Origin": "https://www.instagram.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Sec-Ch-Prefers-Color-Scheme": "light",
    "Sec-Ch-Ua": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-Ch-Ua-Full-Version-List": "\"Not)A;Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"127.0.6533.120\", \"Chromium\";v=\"127.0.6533.120\"",
    "Sec-Ch-Ua-Mobile": "?1",
    "Sec-Ch-Ua-Model": "\"Nexus 5\"",
    "Sec-Ch-Ua-Platform": "\"Android\"",
    "Content-Length": "432",
    "Sec-Ch-Ua-Platform-Version": "\"6.0\"",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": useragents,
    "X-Asbd-Id": "129477",
    "X-Csrftoken": csrftoken,
    "X-Ig-App-Id": "936619743392459",
    "X-Ig-Www-Claim": "0",
    "X-Instagram-Ajax": "1015963884",
    "X-Requested-With": "XMLHttpRequest",
    'Cookie': f'ig_did={ig_did}; datr=AUPXZX4woXx7NTGR5FW5YSb1; ig_nrcb=1; mid={mid}; ps_n=1; ps_l=1;  csrftoken={csrftoken}; dpr=1.125; wd=1264x900'


    }



    response = session.post(url,headers=headers,data=data,cookies=cookies)
    cookies = response.cookies.get_dict()

    first_key,first_value = next(iter(cookies.items()))

    extracted_value =  cookies[first_key]
    cookies  = {

  first_key : extracted_value

  }
    print(Fore.RED+'Done step 2')

    x=  decoder(response)
    return cookies

def get_code(email):
    time.sleep(20)

    url = f'https://api.internal.temp-mail.io/api/v3/email/{email}/messages'

    headers = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'en-US,en;q=0.9',
    'Application-Name': 'web',
    'Application-Version': '2.4.1',
    'Cache-Control': 'no-cache',
    'Origin': 'https://temp-mail.io',
    'Cookie':'_ga=GA1.2.1239562635.1719424024; _gid=GA1.2.1366826056.1721820067; __gads=ID=386ef560517c8945:T=1719424034:RT=1721820071:S=ALNI_MaLrf_1VHq04VCqkSr2dgbqf78Pqg; __gpi=UID=00000e658247d18f:T=1719424034:RT=1721820071:S=ALNI_Mawaem49vDlqhqCRECEXEmfj4KmZA; __eoi=ID=0adeef503080bd61:T=1719424034:RT=1721820071:S=AA-AfjYAqbOVbHeEDsREkcrHbQUu; FCNEC=%5B%5B%22AKsRol_J-H5nWdvVxL51a9KkjFJOw2czENkErIryGhbST9bR-nEIV2-DzsYFx0Zf9CDJFatnf5bLl__phohrbaOWqg0-3RqmufQzWJUvnN7x-9CEwhRH8O62it_mRYeXvapT7PeiYdvLzqReLxH8lKsUFZKODmWQMA%3D%3D%22%5D%5D; _ga_3DVKZSPS3D=GS1.2.1721820068.8.1.1721820564.60.0.0',
    'Pragma': 'no-cache',
    'Priority': 'u=1, i',
    'Referer': 'https://temp-mail.io/',
    'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
    'Sec-Ch-Ua-Mobile': '?1',
    'Sec-Ch-Ua-Platform': '"Android"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'User-Agent': useragents
}


    response = requests.get(url,headers=headers)
    with open("tester.txt",'w') as f:
      f.write(response.text)
    pattern = r'"subject":"(\d{6}) is your Instagram code"'

    match = re.search(pattern, response.text)

    if match:
        code = match.group(1)  # Extract the code from the first capturing group
        new_code  = int((code.strip()))
        print(new_code)
        print(type(new_code))
        print(Fore.RED+'Done step 3')

        print(new_code)
        return new_code
    
    else:
         print("Code not found in the text file.")
         sys.exit()


def ageChecker(csrftoken, ig_did, mid,cookies):
    url = 'https://www.instagram.com/api/v1/web/consent/check_age_eligibility/'

    data = {

        'day': 31,
        'month': 7,
        'year': 1971,
    }

    headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Content-Length": "24",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://www.instagram.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Sec-CH-Prefers-Color-Scheme": "light",
    "Sec-CH-UA": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-CH-UA-Full-Version-List": "\"Not)A;Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"127.0.6533.74\", \"Chromium\";v=\"127.0.6533.74\"",
    "Sec-CH-UA-Mobile": "?1",
    "Sec-CH-UA-Model": "\"Nexus 5\"",
    "Sec-CH-UA-Platform": "\"Android\"",
    "Sec-CH-UA-Platform-Version": "\"6.0\"",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": useragents,
    "X-ASBD-ID": "129477",
    "X-CSRFToken": csrftoken,
    "X-IG-App-ID": "936619743392459",
    "X-IG-WWW-Claim": "0",
    "X-Instagram-Ajax": "1015287874",
    "X-Requested-With": "XMLHttpRequest",
    'Cookie':  f'ig_did={ig_did}; datr=AUPXZX4woXx7NTGR5FW5YSb1; ig_nrcb=1; mid={mid}; ps_n=1; ps_l=1; csrftoken={csrftoken}; rur="EAG\05468047158726\0541753974033:01f75f0143d2c79ad17ffabb74e1ca355d01ff6d8981a1ac5ca831a24138ffbb1887cc00"; dpr=1.125; wd=918x675'

}

    print(Fore.RED+'Done step 4')

    response = session.post(url,headers=headers,data=data,cookies= cookies)
    cookies = response.cookies.get_dict()

    first_key,first_value = next(iter(cookies.items()))

    extracted_value =  cookies[first_key]
    cookies  = {

  first_key : extracted_value

  }
    print(response.status_code)

    x=   decoder(response)
    return cookies


def sendOtp(csrftoken, ig_did, mid,email,cookies):
    url = 'https://www.instagram.com/api/v1/accounts/send_verify_email/'

    data = {

        'device_id': '7vgko51ff6yofe3px8f1c1pzdi1prwvxo1xjgti6oqp1pkkff1fy',
        'email': str(email)
    }

    headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Content-Length": "93",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://www.instagram.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Sec-CH-Prefers-Color-Scheme": "light",
    "Sec-CH-UA": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-CH-UA-Full-Version-List": "\"Not)A;Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"127.0.6533.74\", \"Chromium\";v=\"127.0.6533.74\"",
    "Sec-CH-UA-Mobile": "?1",
    "Sec-CH-UA-Model": "\"Nexus 5\"",
    "Sec-CH-UA-Platform": "\"Android\"",
    "Sec-CH-UA-Platform-Version": "\"6.0\"",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": useragents,
    "X-ASBD-ID": "129477",
    "X-CSRFToken": csrftoken,
    "X-IG-App-ID": "936619743392459",
    "X-IG-WWW-Claim": "0",
    "X-Instagram-Ajax": "1015287874",
    "X-Requested-With": "XMLHttpRequest",
    'Cookie': f'ig_did={ig_did}; datr=AUPXZX4woXx7NTGR5FW5YSb1; ig_nrcb=1; mid={mid}; ps_n=1; ps_l=1; csrftoken={csrftoken}; rur="EAG\05468047158726\0541753974033:01f75f0143d2c79ad17ffabb74e1ca355d01ff6d8981a1ac5ca831a24138ffbb1887cc00"; dpr=1.125; wd=918x675'
}

    response = session.post(url,headers=headers,data=data,cookies=cookies)
    cookies = response.cookies.get_dict()

    first_key,first_value = next(iter(cookies.items()))

    extracted_value =  cookies[first_key]
    cookies  = {

  first_key : extracted_value

  }
    print(Fore.RED+'Done step 5')
    print(response.status_code)

    x=  decoder(response)
    return cookies

def checkOtp(csrftoken, ig_did, mid,email,code, cookies):
    url = 'https://www.instagram.com/api/v1/accounts/check_confirmation_code/'

    data  = {
        
    'code': int(code) ,
    'device_id': '7vgko51ff6yofe3px8f1c1pzdi1prwvxo1xjgti6oqp1pkkff1fy',
    'email': email

}
    headers = {
        
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Content-Length": "107",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://www.instagram.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Sec-CH-Prefers-Color-Scheme": "light",
    "Sec-CH-UA": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-CH-UA-Full-Version-List": "\"Not)A;Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"127.0.6533.74\", \"Chromium\";v=\"127.0.6533.74\"",
    "Sec-CH-UA-Mobile": "?1",
    "Sec-CH-UA-Model": "\"Nexus 5\"",
    "Sec-CH-UA-Platform": "\"Android\"",
    "Sec-CH-UA-Platform-Version": "\"6.0\"",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": useragents,
    "X-ASBD-ID": "129477",
    "X-CSRFToken": csrftoken,
    "X-IG-App-ID": "936619743392459",

    "X-IG-WWW-Claim": "hmac.AR1hwvILdI1QdlcYw57JEmetkok0Es1aHP70B6ERBQOqOas4",
    "X-Instagram-Ajax": "1015289198",
    "X-Requested-With": "XMLHttpRequest",
    'Cookie': f'ig_did={ig_did}; datr=AUPXZX4woXx7NTGR5FW5YSb1; ig_nrcb=1; mid={mid}; ps_n=1; ps_l=1; rur="CCO\05468055173987\0541753976891:01f770c46412b1b4fb521a38dfdddfce226fa252fea1b2848b75718d7a79e81c94d1d79a"; csrftoken={csrftoken}; dpr=1.125; wd=918x675'
}
    
    response = session.post(url,headers=headers,data=data, cookies =cookies )
    cookies = response.cookies.get_dict()

    first_key,first_value = next(iter(cookies.items()))

    extracted_value =  cookies[first_key]
    cookies  = {

  first_key : extracted_value

  }  
    response_text = response.text 
    response_dict = json.loads(response_text)

#   Access the signup_code value
    try:
     signup_code_value = response_dict['signup_code']
    except KeyError:
     sys.exit()   
    print(signup_code_value)
    print(Fore.RED+'Done step 6')

    r = decoder(response)
    return signup_code_value, cookies



def submit(username,email,signup_value,csrftoken, ig_did, mid,cookies ):


    url = 'https://www.instagram.com/api/v1/web/accounts/web_create_ajax/'


    headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Content-Length": "443",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://www.instagram.com",
    "Pragma": "no-cache",
    "Priority": "u=1, i",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Sec-CH-Prefers-Color-Scheme": "light",
    "Sec-CH-UA": "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"",
    "Sec-CH-UA-Full-Version-List": "\"Not)A;Brand\";v=\"99.0.0.0\", \"Google Chrome\";v=\"127.0.6533.74\", \"Chromium\";v=\"127.0.6533.74\"",
    "Sec-CH-UA-Mobile": "?1",
    "Sec-CH-UA-Model": "Nexus 5",
    "Sec-CH-UA-Platform": "Android",
    "Sec-CH-UA-Platform-Version": "6.0",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "User-Agent": useragents,
    "X-ASBD-ID": "129477",
    "X-CSRFToken": csrftoken,
    "X-IG-App-ID": "936619743392459",
    "X-IG-WWW-Claim": "0",
    "X-Instagram-Ajax": "1015289198",
    "X-Requested-With": "XMLHttpRequest",
    'Cookie': f'ig_did={ig_did}; datr=AUPXZX4woXx7NTGR5FW5YSb1; ig_nrcb=1; mid={mid}; ps_n=1; ps_l=1; rur="HIL\05468055118120\0541753978493:01f72dca452577567c0076953dd885abec711d1fd24768f69c36aee2666c667c013c6ce8"; csrftoken={csrftoken}; dpr=1.125; wd=733x675'
}

    timestamp = str(time.time()).split('.')[0]

    data = {

 'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{Setpassword}',
'day' : 31,
'email' : str(email),
'first_name' : username,
'month' : 7,
'username' : username,
'year' : 1971,
'client_id' : '7vgko51ff6yofe3px8f1c1pzdi1prwvxo1xjgti6oqp1pkkff1fy',
'seamless_login_enabled' : 1,
'tos_version' : 'row',
'force_sign_up_code' : str(signup_value),

    }


    response = session.post(url,headers=headers,data=data,cookies =cookies )
    
    print(response.status_code)
    print(Fore.RED+'Done step 7')
    r = decoder(response)
    session.close()
    response_text = response.text
    try:
     response_dict = json.loads(response_text)
     account_created_status = response_dict['account_created']
    except json.JSONDecodeError as e:
      print ("JSON ERROR")
    if 1==1:
            
            token =" "    # enter your bot token here
            ID =" "      # enter your telegram id you can find using telegram bot name @userinfo
            requests.post(f'https://api.telegram.org/bot{token}/sendMessage?chat_id={ID}&text=username:{username}%20|%20Password:%20ASDF12345%23%20|%20email%20=%20{email}')

      
    

##############

csrftoken, ig_did, mid = header_cookie()

def  called():

 username = generate_random_username()
 print(username)
# csrftoken, ig_did, mid = header_cookie()
 email,cookies =  get_email()
 cookies = imp_info(username,csrftoken, ig_did, mid,email, cookies)
 ageChecker(csrftoken, ig_did, mid,cookies)
 cookies= sendOtp(csrftoken, ig_did, mid,email,cookies)
 Verifycode = get_code(email)
 signup_value ,cookies = checkOtp(csrftoken, ig_did, mid,email,Verifycode, cookies)
 submit(username,email,signup_value,csrftoken, ig_did, mid , cookies)

for i in range(0,5):
 called()
    
