# Encrypted Chat Application
#### A rudimentary end-to-end encrypted chat server and client.

This is networking code made for a group project that I wrote (mostly) in a weekend. I decided
to release it because I enjoyed working on it and it was the first networked program I ever made
with a protocol. I am aware that it has *many* problems. Most of these were not fixed because our
goal was to quickly write simple code that worked for the school project. Please note that there was
more of the project than this. This repository only includes the code that I (Alejandro Ramos) wrote
and contributed, which was mainly the protocol, the client (not including the GUI), and the server.

## Flaws in the System
There are a number of flaws both in the protocol and in the implementation. I'll briefly outline a
few of the larger ones. We knew about most of these while we were working on the project, but we
didn't fix them due to time constraints as this was done for a school project.

1. The users' RSA private keys are stored on the server. They are stored encrypted but they are
still stored on the server. This is unideal because while the private keys are encrypted, they are
only as strong as the user's password. This means that if someone were to find out a users password,
they can get the private keys and read all messages the user has sent and recieved. This problem
multiplies when the server is storing every user's private key because an attacker can attempt to
guess multiple users' passwords at once.

2. The system requires an excessive amount of data to be transferred with each message. Even the
smallest messages require the client to send 1042 bytes of data to the server. 1024 bytes are just
to send the new RSA encrypted AES keys for each message. In fact, the length of the full encrypted
message can be over double the length of the plaintext message until the message reaches 1041 bytes.
Most instant messages are well below 1KB, and the encryption protocol should take this into
consideration and try to optimize for smaller messages while still changing the message encryption
key frequently.

3. The client is not implemented well. It was done quickly and in such a way that makes
multithreading very difficult to do. Most of the methods in the client will send a request, and then
wait for the next response the server sends, not checking if it is the correct response or not.
For example when we tested the multithreaded client GUI, if a user tried to do things too fast (like
click on multiple message tabs or send messages), it would break.

## Networking Protocol
I made a simple and *very* fragile protocol for messages between the clients and the server. We
realized that we would need a protocol because this is not a simple chat server, where every network
message is a chat message and the server can just pass each message to the other party without
having to interpret it. Shown below is a table that outlines the data requirements of each command.
Commands are listed in rough chronological order, based on when a client would likely use each
command.

### The Commands
Note that numbers in (parentheses) represent the number of bytes for each part of the message. Also
note that each request/response message includes its type in the first 3 characters of each message.
For example, an NME request consists of the letters 'N', 'M', and 'E', then 16 letters for the user's
desired name.

| Request                                                                                              | Response                                                                                                                        |
|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| REG(3) + username(16) + publicKey(550) + encPrivateKey(2384)                                         | REG(3) + userID(1)                                                                                                              |
| LOG(3) + A(1) + username(16)                                                                         | LOG(3) + result(1) + \[if 'Y': userID(1) + publicKey(550) + encPrivateKey(2384) + loginCode(8)\]                                |
| LOG(3) + B(1) + signedCode(512)                                                                      | LOG(3) + result(1)                                                                                                              |
| NME(3) + username(16)                                                                                | NME(3) + result(1)                                                                                                              |
| PWD(3) + newPrivateKey(2384) + signature(512)                                                        | PWD(3) + result(1)                                                                                                              |
| LST(3)                                                                                               | LST(3) + numUsers(1) + \[for each: userID(1) + username(16)\]                                                                   |
| PUB(3) + recipientID(1)                                                                              | PUB(3) + userID(1) + publicKey(550)                                                                                             |
| MSG(3) + recipientID(1) + numOfAesBlocks(1) + authorKey(512) + recipientKey(512) + aesBlocks(num*16) | MSG(3)                                                                                                                          |
| GET(3) + authorID(1) + numToGet(1)                                                                   | GET(3) + numOfMessages(1) + \[for each: authorID(1) + numOfBlocks(1) + authorKey(512) + recipientKey(512) + aesBlocks(num*16)\] |

### REG
#### To register a new user account
The client sends their desired username, their X.509 encoded 4096-bit RSA public key. The client
also sends their AES-256 encrypted PKCS #8 encoded private key.

The server responds with a new User ID for the client.

Implementation note: currently no checking is done to make sure the client has a unique username.
This should be added and the protocol be slightly amended to indicate if the operation was
successful.

Protocol note: there is no way for the server to verify that the given public key matches the given
private key.

### LOG
#### To log in to the server
The client must send which step of the login process they are engaging in: A (step 1) or B (step 2).
If A, the client sends their username. If B, the client sends a signature of the code given by the
server, generated using the client's private key.

The server responds based on login step given by the client. If A, and the username exists in the
database, the server responds with the letter 'Y', the user's ID, their public key, their encrypted
private key, and a login code. If the username is not already registered, it just responds with the
letter 'N'. If we are on step B, the server responds with the letter 'S' or 'F' depending if the
signature matches the login code and the client's public key.

Implementation note: the login code used is just the Unix timestamp generated at the time the server
receives the request. This allows for a replay attack. An attacker can make their own login request
(with a different client) at the same time as the victim. If it is in the same second, they will be
given the same timestamp. They can then intercept the client's response and send the same signature
to the server. They are now logged in as the other user. To prevent this attack, the server should
not give a user the same login code twice. This can be done easily with randomized login codes.

### NME
#### To change your username
The client sends the desired username to the server.

The server responds with 'S' or 'F' depending if the username is already used by another user.

### PWD
#### To change your password
The client sends a new version of their encrypted private key to the server. This is encrypted with
the user's new password. The client also sends a signature of this encrypted key, generated from the
private key.

The server responds with 'S' if the signature matches the new encrypted private key and the known
public key. It responds with 'F' if it does not.

### LST
#### To list the registered users
The client simply sends the name of the command with no other parameters.

The server responds with the number of users, and for each user it sends their User ID and their
username.

Implementation note: User IDs are generated from the index of the User array and stored in a Java
byte. Java bytes have a maximum positive value of 127, meaning that the server can only support that
many users until it breaks. Clients will receive negative IDs during login and when listing the
users. These clients will be unable to send or receive messages, and no one can retrieve their
public keys.

### PUB
#### To get a user's public key
The client sends the User ID of the user whose public key they want.

The server responds with the requested User ID and their public key.

### MSG
#### To send a message to a user
The client sends the recipient's ID, the number of 128-bit AES blocks created after encrypting the
message, the AES key encrypted with the author's public key, the AES key encrypted with the
recipient's public key, and the encrypted message.

The server simply responds with the name of the command.

Protocol note: to make this system more robust when sending lots of messages at the same time, there
should be a way for the client to ensure that every message was delivered to the server, and
delivered in the correct order.

### GET
#### To get a conversation with a user
The client sends the User ID of the other party in the conversation they want to retrieve. The
client also sends the number of messages they want to retrieve.

The server responds with the other party's User ID and the number of messages it is sending. This
number can be less than the number of messages requested if there aren't that many messages in the
conversation. For each message, the server also sends the author's ID, the number of AES blocks in
the message, the AES key encrypted for the author, the AES key encrypted for the recipient, and the
encrypted message.

Implementation note: the server does not need to send the encryption keys for both parties in the
conversation. The server knows which part of the message contains each key, so it can select the
correct key for the client that used the GET function.

## LICENSE
Copyright (c) 2022 Alejandro Ramos

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
