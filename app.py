# from flask_bcrypt import Bcrypt

# bcrypt = Bcrypt()

# password = 'supersecretpassword'
# password1 = 'supersecretpassword'
# hashed_password = bcrypt.generate_password_hash(password)
# print(hashed_password)
# hashed_password = bcrypt.generate_password_hash(password1)
# print(hashed_password)


# check = bcrypt.check_password_hash(hashed_password, 'supersecretpassword')
# print(check)

from werkzeug.security import generate_password_hash, check_password_hash

hashed_pass = generate_password_hash('mypassword')
print(hashed_pass)
check = check_password_hash(hashed_pass, 'mypassword')
print(check)
