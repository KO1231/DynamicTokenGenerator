from jwt.algorithms import RSAAlgorithm
import jwt
import json
import time


def _get_header(credential_folder):
    return {
        "alg": "RS256",
        "typ": "JWT",
        "kid": _get_kid(credential_folder)
    }


def _get_private(credential_folder):
    private_path = credential_folder.joinpath("PRIVATE")
    if not private_path.exists():
        raise RuntimeError("PRIVATE File is not exists.")

    with private_path.open(mode="rt") as private_file:
        private = json.load(private_file)
    return private


def _get_payload(credential_folder, jwt_exp: int, token_exp: int):
    if not (0 < jwt_exp <= (60 * 30)):
        raise RuntimeError("jwt_exp out of range.")

    if not (0 < token_exp <= (60 * 60 * 24 * 30)):
        raise RuntimeError("token_exp out of range.")

    cid = _get_cid(credential_folder)
    return {
        "iss": cid,
        "sub": cid,
        "aud": "https://api.line.me/",
        "exp": int(time.time()) + jwt_exp,
        "token_exp": token_exp
    }


def _get_kid(credential_folder):
    kid_path = credential_folder.joinpath("KID")
    if not kid_path.exists():
        raise RuntimeError("KID File is not exists.")

    with kid_path.open(mode="rt") as kid_file:
        kid = kid_file.read()
    return kid


def _get_cid(credential_folder):
    cid_path = credential_folder.joinpath("CHANNEL_ID")
    if not cid_path.exists():
        raise RuntimeError("Channel ID File is not exists.")

    with cid_path.open(mode="rt") as cid_file:
        cid = cid_file.read()
    return cid


def get_jwt(credential_folder, jwt_exp: int = 60 * 30, token_exp: int = 60 * 60 * 24 * 30):
    jwt_sign_key = RSAAlgorithm.from_jwk(_get_private(credential_folder))
    return jwt.encode(
        payload= _get_payload(credential_folder, jwt_exp, token_exp),
        key= jwt_sign_key,
        algorithm= "RS256",
        headers= _get_header(credential_folder),
        json_encoder= None
    )
