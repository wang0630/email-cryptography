# email-cryptography
Mimic a CCA-secure scheme to encrypt/decrypt messages and prevent replay attack by recording hash value of the tag.

## Run
Create virtual env using `python3 -m venv venv && source venv/bin/activate`<br/>
Then install all deps using `pip install -r requirements.txt`<br/>
Finally, run the program with `python3 main.py`.

## Encryption procedure
1. Use AES-128-OFB to generate ciphertext `c`.
2. Use HMAC-SHA256 to calculate tag `MAC(c) = t` using ciphertext `c`(Encrypt-then-hash).
3. Use SHA-256 to calculate hash value `H(t)` using tag `t` and put the hash into a set.
4. Send message `m = <c, t>`.

## Decryption procedure
1. Use SHA-256 to calculate hash value `H(t)` using tag `t`, and check if this hash value is indeed in the set or not. If not, that means this tag `t`
is either modified or has been processed already, and the message is simply discarded. 
2. Use HMAC-SHA256 to calculate tag `MAC(c) = t`, and continues only if `Vrfy(c, t) = 1`.
3. Upon this point, we confirm that this message is not a replay, and the tag is verified. Hence, we could safely decrypt the message.
