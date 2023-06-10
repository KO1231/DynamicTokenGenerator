from jwcrypto import jwk
from pathlib import Path
import json

output_private = "PRIVATE"
output_public = "PUBLIC"


def generate(credential_folder: Path):
    pri_filepath = credential_folder.joinpath(output_private)
    pub_filepath = credential_folder.joinpath(output_public)

    if pub_filepath.exists() or pri_filepath.exists():
        raise RuntimeError("PUBLIC or PRIVATE key's file is already exists")

    key = jwk.JWK.generate(kty="RSA", alg="RS256", use="sig", size=2048)

    pri = key.export_private()
    pub = key.export_public()

    with pri_filepath.open(mode="wt") as private_file:
        private_file.write(json.dumps(json.loads(pri), indent=2))

    with pub_filepath.open(mode="wt") as public_file:
        public_file.write(json.dumps(json.loads(pub), indent=2))


if __name__ == "__main__":
    credential_folder = Path(__file__).parent.parent.joinpath("credential")
    credential_folder.mkdir(exist_ok=True)
    generate(credential_folder)
