# Encrypted Chat Application
#### A rudimentary end-to-end encrypted chat server and client.

This is networking code made for a group project that I wrote (mostly) in a weekend. I decided
to release it because I enjoyed working on it and it was the first networked program I ever made
with a protocol. I am aware that it has *many* problems. Many of these were not fixed because my
goal was to quickly write simple code that worked for the school project. Some of these were not
fixed because I didn't realize it until later.

In the future I may write a proper list of flaws in the system. One of the larger flaws is that the
system requires a lot of data to be transferred, causing a lot of overhead for instant messaging.
There are also problems with this implementation, especially that the client has problems when run
with multiple threads because it only listens for the response to the last command it sends. In our
tests with a graphical UI we had to be careful not to perform actions too quickly, or else the
listening could become out of sync with the sending and the client would fail.

## Networking protocol
I made a simple and *very* fragile protocol for messages between the clients and the server. We
realized that we would need a protocol because this is not a simple chat server, where every network
message is a chat message and the server can just pass each message to the other party without
having to interpret it. Shown below is a table that outlines the data requirements of each command.
Commands are listed in rough chronological order, based on when a client would likely use each
command.

### The Commands
Note that numbers in (parentheses) represent the number of bytes for each part of the message

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
