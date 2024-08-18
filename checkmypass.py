import requests
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the API and try again.")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if hash_to_check == h:
            return count
    return 0


def pwned_api_check(password):
    sha1password = (hashlib.sha1(password.encode("utf-8"))
                    .hexdigest()
                    .upper())
    first5_cha, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_cha)
    return get_password_leaks_count(response, tail)


def main(args):
    for pwd in args:
        count = pwned_api_check(pwd)
        if count:
            print(f"{pwd} was found {count} times... you should change your password.")
        else:
            print(f"{pwd} was NOT found. Carry on!")
    return "done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))