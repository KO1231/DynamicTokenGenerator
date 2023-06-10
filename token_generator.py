from pathlib import Path
import jwt_util as jutil
import requests
import time


def generate(token_exp: int = 60 * 60 * 24 * 30):
    jwt = jutil.get_jwt(
        credential_folder=_get_credential_folder(),
        jwt_exp=10,
        token_exp=token_exp
    )

    response = requests.post(
        url="https://api.line.me/oauth2/v2.1/token",
        data={
            'grant_type': "client_credentials",
            'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            'client_assertion': jwt,
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    if response.status_code != 200:
        print(response.text)
        raise RuntimeError(f"RESPONSE CODE -> {response.status_code}")

    response_json = response.json()
    response_json = {
        "token_id": response_json["key_id"],
        "token": response_json["access_token"],
        "expire_date": int(time.time()) + int(response_json["expires_in"]) - (60 * 5)
    }

    return response_json


def get_valid_tokenids() -> list:
    jwt = jutil.get_jwt(
        credential_folder=_get_credential_folder(),
        jwt_exp=10,
        token_exp=1
    )

    response = requests.get(
        url="https://api.line.me/oauth2/v2.1/tokens/kid",
        params={
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt
        }
    )

    if response.status_code != 200:
        print(response.text)
        raise RuntimeError(f"RESPONSE CODE -> {response.status_code}")

    return response.json()["kids"]

def _delete_invalid_tokens(valid_token_kids: list) -> list:
    token_file = Path("TOKEN")
    if not token_file.exists():
        with token_file.open(mode="wt") as f:
            f.write("[]")
        return []

    with token_file.open(mode="rt") as f:
        tokens = eval(f.read())
    valids = [token for token in tokens if token["token_id"] in valid_token_kids]
    with token_file.open(mode="wt") as f:
        f.write(str(valids))

    return valids

def _get_credential_folder():
    credential_folder = Path(__file__).parent.joinpath("credential")
    credential_folder.mkdir(exist_ok=True)
    return credential_folder

def main(force_generate: bool = False):
    # Token limit check
    valid_ids = get_valid_tokenids()
    valid_tokens = _delete_invalid_tokens(valid_ids)
    if len(valid_tokens) > 0 and not force_generate:
        with open("TOKEN", mode="wt") as f:
            f.write(str(valid_tokens))
        return valid_tokens

    if len(valid_ids) >= 30:
        raise RuntimeError("Can't generate token because amount limit.")

    # Generate
    new_token = generate(60)
    valid_tokens.append(new_token)

    # Add new token to TOKENS
    with open("TOKEN", mode="wt") as f:
        f.write(str(valid_tokens))
    return valid_tokens

if __name__ == '__main__':
    main()
