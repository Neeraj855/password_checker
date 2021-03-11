import requests
import hashlib
import sys


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RecursionError(
            f'Error fetching: {res.status_code}, check the api again')
    return res


def pasword_leak_count(hashes, hash_to_check):
    hashes = (line.split(':')for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest()
    first5_charaters, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_charaters)
    return pasword_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times.... you shold reconsider it')
        else:
            print(f'{password} was NOT found. Carry on!!!')
    return 'done'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
