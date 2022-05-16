from src.system import *

if __name__ == '__main__':
    system = System()
    # A message is sent
    ciphertext, tag = system.encrypt('./test.txt')
    # Try to re-verify message to mimic replay attack
    sent = 2
    while sent > 0:
        try:
            if system.verify(tag):
                print(f'The tag is correct')
            else:
                print(f'Incorrect tag')
        except Exception as e:
            print(f'Other error has occurred. {e}')

        sent -= 1
