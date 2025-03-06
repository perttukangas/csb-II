import sys
import hashlib
import base64


def test_password(passhash, candidates):
    # protocol$salt$hash
    protocol, salt, hash = passhash.split("$")
    decoded_salt = base64.b64decode(salt)
    decoded_hash = base64.b64decode(hash)

    for candidate in candidates:
        candidate_hash = hashlib.sha384(
            decoded_salt + candidate.encode("utf-8")
        ).digest()

        if candidate_hash == decoded_hash:
            return candidate

    return None


def main(argv):
    passhash = argv[1]
    print("Given hash:", passhash)
    fname = argv[2]
    candidates = [p.strip() for p in open(fname)]
    print(test_password(passhash, candidates))


# This makes sure the main function is not called immediatedly
# when TMC imports this module
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python %s hash filename" % sys.argv[0])
    else:
        main(sys.argv)
