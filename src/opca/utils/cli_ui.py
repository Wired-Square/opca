# opca/utils/cli-ui.py

import getpass

def get_confirmed_password():
    while True:
        password = getpass.getpass('🔑 Enter your password: ')
        confirm_password = getpass.getpass('🔁 Confirm your password: ')
        if password == confirm_password:
            print('✅ Password confirmed.')
            return password
        else:
            print('❌ Passwords do not match. Please try again.\n')