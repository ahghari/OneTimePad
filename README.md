# OneTimePad
In cryptography, the one-time pad (OTP) is an encryption technique that cannot be cracked, 
but requires the use of a one-time pre-shared key the same size as, or longer than, the message being sent.

This is a native C implementation of OTP that encrypts a file or pipe input.
Every byte/character of the input is encrypted with a generated (pseudo-)random byte/character key.
The result output (encrypted file and key file or pipe output and key file) contains the encrypted bytes/characters 
and the key bytes/characters of same size of the input.
The source-code can be compiled with any POSIX-compiler including the platforms pthread-library 
and with Microsofts Visual-C++-compiler.
