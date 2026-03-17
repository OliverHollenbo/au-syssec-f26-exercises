# Exercises: Secure Implementation, Weak Entropy and Authentication Mechanisms

## Exercise 1: Weak Entropy

I have a big problem: When preparing this exercise last Friday, I encrypted a
very important file.  Unfortunately, I forgot to save the key, and now I cannot
access the data anymore.  Can you help me decrypt it?

This is the command that I used:
```
$ python encrypt.py plain.txt ciphertext.bin
```
The `time()` function measures the number of seconds since January 1st, 1970 UTC.

## Exercise 2: Implement RSA without branches

## Objective

In this exercise, you will remove the main source of side-channel leakage of the RSA decryption algorithm.
This will involve reformulating the exponentiation algorithm to replaces branches by a conditional selection operation.

#### Exponentiation

The provided RSA implementation has been refactored to accept strings as input, by encoding/decoding byte strings into integers.
It also implements its own decryption algorithm, using a square-multiply that scans bits of the exponent from left to right.

```
python3 rsa.py 1024 "plaintext"
```

The algorithm for exponentiation evaluates the following recurrence:

$$
x^y =
\begin{cases}
1, & \text{if } y = 0, \\
\left(x^2\right)^{y/2}, & \text{if } y \text{ is even}, \\
x \cdot \left(x^{y-1}\right), & \text{if } y \text{ is odd}.
\end{cases}
$$

For reference, we include two versions of this idea (scanning the exponent from left to right, and from right to left).

### Tasks
1. Reformulate the exponentiation algorithm to remove the branches based on key bits.
   <br>**Hint**: think of how to use a single bit as a selector between two values.
3. Find a way to bound the number of iterations of the algorithm such that it does not leak how long the private exponent is.
   <br>**Hint**: think of how to use a public parameter to fix a maximum number of iterations.
4. **BONUS**: Implement the [Montgomery Ladder](https://en.wikipedia.org/wiki/Exponentiation_by_squaring#Montgomery's_ladder_technique) algorithm.

## Exercise 3: Authentication Mechanisms

We will strengthen your authentication mechanisms by adopting a password manager and hardening its default configuration.

1. First, find a password manager that is compatible with your personal choices of operating system and mobile device. There are many options here, and some popular suggestions are LastPass, 1Password, Dashlane and BitWarden. An open-source solution with somewhat lower usability is KeePass. You should favor any options that support multi-factor authentication as a free option, not requiring a paid subscription.

**Note**: If you already are a user of a password manager, use this exercise to _harden_ your setup instead.

2. Install and create an account in your password manager software. Pick a long passphrase containing at least 6 words by using the [Diceware](https://diceware.dmuth.org/) (or a similar) method.

3. Use the [have i been pwned](https://haveibeenpwned.com/) service to detect if any of your credentials was observed in a data breach included in their database.

4. Migrate some accounts to your new password manager by resetting their passwords and picking the random replacements suggested by the password manager. We do not suggest migrating your e-mail account, since that will be needed to recover your password manager account itself in case the passphrase is lost.

5. Find what options are supported for multi-factor authentication in your password manager, and pick one to setup.

6. Attempt to harden your password manager configuration by finding out what is the current choice of iterations for the password hashing function -- typically [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) -- and what the recommended best practices are.

7. Think of other ways to harden your account further, for example using it strictly in offline mode (to reduce attack surface) or a secure backup policy for the unlikely case of losing access to your passphrase.
