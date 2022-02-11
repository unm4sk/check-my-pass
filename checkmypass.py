# hackers use dictionary attacks, like in Python {}
import requests  #* allow us to make requests to get something back
import hashlib
import sys

#* need a hashed password - using SHA1
#! not super secure - need a ksecurity - 5 first characters of a password 

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)  # get a response #! without query_char!
    if res.status_code != 200:  # getting [400] - not good! need [200]!
        raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again!')
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())  # splitlines - split by lines
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0  # if nothing has been matched!

def pwned_api_check(password):
    # check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)
    #* response.text - get all hashes that match the beginning of hashed password 
    # hash:how_many_times_occured

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done'

main(sys.argv[1:])