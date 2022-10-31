from hashlib import sha1


def crack_sha1_hash(hash, use_salts=False):
    # filehandler = open("top-1000-passwords.txt", "r")
    with open("top-10000-passwords.txt", "r") as filehandler:
        for line in filehandler:
            password = line.strip()

            # When using a salt
            if use_salts:
                with open("known-salts.txt") as salts:
                    for salt in salts:
                        salt = salt.strip()
                        to_hash = salt + password
                        hashed = sha1(to_hash.encode("utf-8")).hexdigest()
                        if sha1((salt + password).encode("utf-8")).hexdigest() == hash or sha1((password + salt).encode("utf-8")).hexdigest() == hash:
                            return password

            # use_salts = False
            elif sha1(password.encode("utf-8")).hexdigest() == hash:
                return password

    # Runs only when no password from top-1000-passwords matchs the hash
    return "PASSWORD NOT IN DATABASE"


result = crack_sha1_hash("ea3f62d498e3b98557f9f9cd0d905028b3b019e1", True)
print(result)


# b305921a3723cd5d70a375cd21a61e60aabb84ec should return "sammy123"
# c7ab388a5ebefbf4d550652f1eb4d833e5316e3e should return "abacab"
# 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 should return "password"
# Here are some hashed passwords to test the function with when use_salts is set to True:

# 53d8b3dc9d39f0184144674e310185e41a87ffd5 should return "superman"
# da5a4e8cf89539e66097acd2f8af128acae2f8ae should return "q1w2e3r4t5"
# ea3f62d498e3b98557f9f9cd0d905028b3b019e1 should return "bubbles1"
