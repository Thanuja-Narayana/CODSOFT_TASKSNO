import getpass

correct_username = "admin"
correct_password = "admin123"

attempts = 3

while attempts > 0:

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    if username == correct_username and password == correct_password:
        print("Login Successful")
        break

    else:
        attempts -= 1
        print("Wrong Credentials")
        print("Attempts Left:", attempts)

if attempts == 0:
    print("Account Locked")