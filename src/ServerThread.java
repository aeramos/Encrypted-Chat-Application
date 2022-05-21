/*
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
 */

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class ServerThread implements Runnable {
    private final Socket socket;
    private final InputStream socketInput;
    private final OutputStream socketOutput;
    private final List<String> usernames;
    private final List<PublicKey> publicKeys;
    private final List<byte[]> privateKeys;
    private final List<Message> messages;

    byte[] loginTimestamp = null;

    private byte id = -1;

    public ServerThread(Socket socket, List<String> usernames, List<PublicKey> publicKeys, List<byte[]> privateKeys, List<Message> messages) throws IOException {
        this.socket = socket;
        this.socketInput = socket.getInputStream();
        this.socketOutput = socket.getOutputStream();
        this.usernames = usernames;
        this.publicKeys = publicKeys;
        this.privateKeys = privateKeys;
        this.messages = messages;
    }

    private static String byteToUsername(byte[] bytes) {
        String username = "";
        for (int i = 0; i < 16; i++) {
            if (bytes[i] == 0) {
                break;
            }
            username += (char)bytes[i];
        }
        return username;
    }

    @Override
    public void run() {
        while (socket.isConnected()) {
            byte[] input = new byte[3];
            try {
                socketInput.readNBytes(input, 0, 3);
                String command = "" + (char)(input[0]) + (char)(input[1]) + (char)(input[2]);
                switch (command) {
                    case "PWD":
                        byte[] newPrivate = socketInput.readNBytes(2384);
                        byte[] signature = socketInput.readNBytes(512);
                        if (verifySigRSA(newPrivate, signature, this.publicKeys.get(this.id))) {
                            this.privateKeys.set(this.id, newPrivate);
                            socketOutput.write(new byte[] {'P', 'W', 'D', 'S'});
                        } else {
                            socketOutput.write(new byte[] {'P', 'W', 'D', 'F'});
                        }
                        break;
                    case "NME":
                        input = socketInput.readNBytes(16);
                        String username = byteToUsername(input);
                        input = new byte[] {'N', 'M', 'E', 0};
                        if (usernames.contains(username)) {
                            input[3] = 'F';
                        } else {
                            input[3] = 'S';
                            usernames.set(this.id, username);
                        }
                        socketOutput.write(input);
                        break;
                    case "LOG":
                        input = socketInput.readNBytes(1);
                        if (input[0] == 'A') {
                            input = socketInput.readNBytes(16);
                            username = byteToUsername(input);
                            byte index = (byte)usernames.indexOf(username);
                            if (index != -1) { // 'Y'
                                this.id = index;
                                input = new byte[3 + 2 + 550 + 2384 + 8];
                                input[0] = 'L';
                                input[1] = 'O';
                                input[2] = 'G';
                                input[3] = 'Y';
                                input[4] = index;
                                System.arraycopy(publicKeys.get(index).getEncoded(), 0, input, 5, 550);
                                System.arraycopy(privateKeys.get(index), 0, input, 5 + 550, 2384);
                                BigInteger time = BigInteger.valueOf(Instant.now().getEpochSecond());
                                this.loginTimestamp = time.toByteArray();
                                System.arraycopy(this.loginTimestamp, 0, input, 5 + 550 + 2384, this.loginTimestamp.length);
                                socketOutput.write(input);
                            } else { // 'N'
                                socketOutput.write(new byte[]{'L', 'O', 'G', 'N'});
                            }
                        } else { // first byte is 'B'
                            input = socketInput.readNBytes(512);
                            if (verifySigRSA(loginTimestamp, input, this.publicKeys.get(this.id))) {
                                this.loginTimestamp = new byte[0];
                                socketOutput.write(new byte[]{'L', 'O', 'G', 'S'});
                            } else {
                                socketOutput.write(new byte[]{'L', 'O', 'G', 'F'});
                            }
                        }
                        break;
                    case "REG":
                        this.id = (byte)this.usernames.size();
                        usernames.add(byteToUsername(socketInput.readNBytes(16)));
                        publicKeys.add(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(socketInput.readNBytes(550))));
                        privateKeys.add(socketInput.readNBytes(2384));
                        socketOutput.write(new byte[]{'R', 'E', 'G', this.id});
                        break;
                    case "LST":
                        input = new byte[4 + (17 * usernames.size())];
                        input[0] = 'L';
                        input[1] = 'S';
                        input[2] = 'T';
                        input[3] = (byte)usernames.size();
                        for (int i = 0; i < usernames.size(); i++) {
                            input[4 + (i * 17)] = (byte)i;
                            byte[] usrName = usernames.get(i).getBytes(StandardCharsets.US_ASCII);
                            System.arraycopy(usrName, 0, input, 5 + (i * 17), usrName.length);
                        }
                        socketOutput.write(input);
                        break;
                    case "PUB":
                        byte index = socketInput.readNBytes(1)[0];
                        input = new byte[3 + 1 + 550];
                        input[0] = 'P';
                        input[1] = 'U';
                        input[2] = 'B';
                        input[3] = index;
                        System.arraycopy(publicKeys.get(index).getEncoded(), 0, input, 4, 550);
                        socketOutput.write(input);
                        break;
                    case "MSG":
                        byte recipientID = socketInput.readNBytes(1)[0];
                        this.messages.add(new Message(this.id, recipientID, socketInput.readNBytes(512 + 512 + (16 * socketInput.readNBytes(1)[0]))));
                        break;
                    case "GET":
                        byte authorID = socketInput.readNBytes(1)[0];
                        int requestedNumber = socketInput.readNBytes(1)[0];
                        // GET + number of messages
                        int responseLength = 3 + 1;
                        ArrayList<Message> requestedMessages = new ArrayList<>(requestedNumber);
                        for (int i = this.messages.size() - 1; i >= 0; i--) {
                            Message message = this.messages.get(i);
                            if ((message.authorID == authorID && message.recipientID == this.id) || (message.authorID == this.id && message.recipientID == authorID)) {
                                requestedMessages.add(message);
                                // authorID + numberofblocks + (2 keys + blocks)
                                responseLength += 2 + message.message.length;
                            }
                            if (requestedMessages.size() == requestedNumber) {
                                break;
                            }
                        }
                        input = new byte[responseLength];
                        input[0] = 'G';
                        input[1] = 'E';
                        input[2] = 'T';
                        input[3] = (byte)requestedMessages.size();
                        int pointer = 4;
                        for (int i = requestedMessages.size() - 1; i >= 0; i--) {
                            Message message = requestedMessages.get(i);
                            byte[] msg = message.message;
                            input[pointer++] = message.authorID;
                            input[pointer++] = (byte)((msg.length - (512 * 2)) / 16);
                            System.arraycopy(msg, 0, input, pointer, msg.length);
                            pointer += msg.length;
                        }
                        socketOutput.write(input);
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        System.out.println("Socket closed. Disconnecting from " + socket.getInetAddress() + ":" + socket.getPort());
    }

    public static boolean verifySigRSA(byte[] input, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signatureInstance = Signature.getInstance("SHA256withRSA");
        signatureInstance.initVerify(publicKey);
        signatureInstance.update(input);
        return signatureInstance.verify(signature);
    }
}
