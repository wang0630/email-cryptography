from src.system import *

if __name__ == '__main__':
    system = System()
    # A message is sent
    ciphertext, tag = system.encrypt('./test.txt')

    # Try to re-verify message to mimic replay attack
    sent = 2
    while sent > 0:
        try:
            # Receive the message, check the tag first
            if system.verify(tag):
                print(f'The tag is correct')
                # Write ciphertext down to compare length
                with open('result.txt', 'wb') as fd:
                    fd.write(ciphertext)
            else:
                print(f'Incorrect tag')
        except Exception as e:
            print(f'Other error has occurred. {e}')

        sent -= 1
