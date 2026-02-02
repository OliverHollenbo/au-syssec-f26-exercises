# Exercises: Symmetric Encryption

**Goal of the day:** \
Today you will see how AES can be used in different *Modes of Operation*, and the security properties given by the different modes. 

We will look at ECB, CBC, CTR and GCM mode - other modes exist.

We'll be encrypting images - that way you'll be able to clearly see what's going on. 
The introduction to the PPM file format is **JUST for reference - The code shown here is also within the ppmcrypt.py file.** 

**Task Overview:** 
Your job is to extend the `ppmcrypt.py` file provided. All the places to extend are denoted by the following comments: 

```
\# --------- add your code here -------- 
... 
\# ----- end add your code here --------
```

You are to implement encryption and decryption using the different modes of operation, and perform a few manipulations on the ciphertexts. 
In the ppmcrypt.py file we have supplied the functions "task1", "task2", and so forth. 
Run the code with the following command in your terminal:
```
python3 ppmcrypt.py
```
In the *main* function (bottom of the ppmcrypt.py file) remove the \# sign to run the task2, task3, task4 and task5 functions, and use these to separate the tasks. 


## Preliminaries - Installing Python, the PyCryptodome library, and ImageMagick

To get started, install Python, the PyCryptodome library, and ImageMagick. \
We recommend using Visual Studio Code (VS Code) for writing your code, as it has many great extensions. A useful one for today is named 'PBM/PPM/PGM Viewer for Visual Studio Code', which lets you look at the PPM images inside VS Code. 

**In the following, pick according to the Operating System on your machine:**
### Windows - (not for Mac or Linux users)
The latest Python version can be downloaded from Microsoft Store

### Mac - (not for Windows or Linux users)
Install Homebrew
Install Python through Homebrew with 
```
brew install python
```
(See https://codedamn.com/news/python/how-to-install-python-on-macos-with-brew for help on brew and Python for mac)

### Ubuntu 24.04 / WSL - (not for Windows or Mac users)

```
sudo apt install python3 imagemagick python3-pycryptodome
```

If the above did not work and module `Crypto` cannot be found, create a virtual environment.

```
python -m venv env
source env/bin/activate
pip install pycryptodome
```

### Arch Linux - (not for Windows or Mac users)

```
sudo pacman -S python python-pycryptodome imagemagick
```

## PPM (Just for reference) -- A Brief Explanation of a Simple Image File Format

**DO NOT blindly copy-paste the following pieces of code - this section is for reference only**

Since looking at hex dumps can be a bit tiring, we are going to encrypt
pictures in the next exercises.

To this end, we use the Portable Pixel Map (PPM) format, which is a very simple
file format.
It starts with a human-readable header containing the dimensions of the image
(and the maximum value in each channel which is 255 in our case).
```
P6
<width> <height>
# The header can also contain comments which start with a # and continue until the end of the line.
255
```
This header is followed by n = 3 * width * height bytes.  Each pixel is stored
in three consecutive bytes which contain its red, green, and blue values.  The
pixels themselves are stored row by row.

PPM is quite inefficient and uncompressed.  Therefore, you probably don't have
any files in this format.  Some example files are included, but you can also
use other pictures, and convert it as follows (provided you have ImageMagick
installed):
```
$ convert image.png -depth 8 image.ppm
```

To work with these PPM files, we provide you with a Python class `PPMImage`
that can read and write PPM images and gives you easy access to the raw pixel
data.  You can find this class in the file `ppmcrypt.py`.

You can load/modify/store an image as follows:
```python
image = PPMImage.load_from_file(open('image.ppm', 'rb'))
print(f'image width: {image.width} px')
print(f'image height: {image.height} px')
print(f'first 16 bytes of that data: {image.data[:16].hex()}')
# make the first 1000 pixel blue
image.data[:3 * 1000] = bytes.fromhex('0000FF') * 1000
image.write_to_file(open('new_image.ppm', 'wb'))
```

PPM specification: http://netpbm.sourceforge.net/doc/ppm.html


## Exercise 1: Electronic Code Book (ECB)

### The big picture: 
The code for ECB mode is given - encrypt the penguin-image and the flag images with ECB mode and look at the encrypted files. Notice anything?

### The details - how to do it:

**Look through the following parts of ppmcrypt.py:**
1. The main function (bottom of the file)
2. The test functions (bottom of the file)
3. The encrypt and decrypt functions (close to the top)

Read the implementation for ECB encryption and decryption in the `PPMImage` class
using the PyCryptodome library.  Take a look at the
[examples](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-aes)
and [the relevant API
documentation](https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html).

**A piece of useful code:** It takes the "image.ppm" file, loads it, encrypts it with *ecb* mode, and writes the encrypted image back into a file named "image_encrypted.ppm":
```python
image = PPMImage.load_from_file(open('image.ppm', 'rb'))
image.encrypt(key, 'ecb')
image.write_to_file(open('image_encrypted.ppm', 'wb'))
```

Run the function named 'Test1` and open the encrypted image. What do you observe?

Try to modify encrypted pictures, and observe how the picture has changed after decryption.
For this you can use a hex editor, or you just access the `.data` property of
an `PPMImage` instance:
```python
image.data[42] = 0x42  # set the byte at position 42 to the value 0x42
```
Extend the function named `Test1` as follows:
```python
image.encrypt(key, 'ecb')
image.data[42] = 0x42  # This line has been added.
image.write_to_file(open('image_encrypted.ppm', 'wb'))
```

Think about if you can make (somewhat) controlled changes to the picture.


## Exercise 2: Cipher-Block-Chaining (CBC) and Counter Mode (CTR)

### The big picture: 
1. Implement CBC and CTR mode
2. Encrypt images with them and look at the encrypted images
3. Manipulate the ciphertext and decrypt - what happens? (Count pixels)

### The details:
Implement encryption and decryption with CBC and CTR modes analogously to ECB.
It helps to have an image of the modes of operation, so you can see how they work, and what they take as input. 

Note that both modes require an additional value:
- CBC takes an Initialization Vector (IV) (use the `iv` parameter to pass a bytes-object of 16 B)
- CTR takes a nonce (use the `nonce` paraemeter to pass a bytes-object of 8 B)
Since these are required for decryption, we store them in comments in the PPM
header.

What is different compared to ECB?
- Take a look at encrypted images containing different patterns.
- Modify the ciphertext and observe what happens to the plaintext?


## Exercise 3: Tampering with Counter Mode

### The big picture: 
CTR mode has a specific weakness - an encryption of the danish flag (DK) can be thought of as $E_{K}(DK) = (DK \ \ XOR \ \  K)$, where K is the output of the AES-box. How can this be abused?

### The details:
While we cannot see any obvious patterns in the ciphertexts generated by CBC and
CTR, an adversary can still tamper with ciphertext.

To demonstrate this problem with CTR mode, implement the following evil plan:

1. Take the image of the Danish flag `dk.ppm` and encrypt it using CTR mode.
2. Modify the encrypted image *without using the key* such that when decrypted,
   an image of the Swedish flag appears.

NB: You are given an image of the Swedish flag `se.ppm` that has the same
dimensions as `dk.ppm`.

## Exercise 4: Authenticated Encryption

### The big picture: 
Implement GCM mode, encrypt an image, manipulate the ciphertext and try to decrypt - what happens? 

### The details:
We have seen that the modes of operation discussed above (ECB, CBC, CTR) allow
an adversary to modify the plaintext by performing operations on the
ciphertext.

To prevent tampering, we want to use *authenticated encryption*.  Modes of
operations providing this level of security create an authentication tag in
addition to the ciphertext.  When decrypting, this tag can be used to verify
the integrity of a given ciphertext.

- Implement the encryption and decryption with Galois-Counter Mode (GCM).
- Encrypt an image, modify the ciphertext, and try to decrypt the modified
  image. Observe what happens.


## Exercise 5: Are we done yet?

Now that we use authenticated encryption, it should be impossible to tamper
with encrypted images, right?

The file `security.ppm` contains a simple message.
Since we do not believe in the statement:

- Encrypt the file using GCM.
- Try to modify the encrypted file (without using the key) such that decryption
  succeeds, but the resulting image shows a different/modified message

What have you learned by this?

