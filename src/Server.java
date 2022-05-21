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
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class Server {
    private static final List<String> usernames = Collections.synchronizedList(new LinkedList<>());
    private static final List<PublicKey> publicKeys = Collections.synchronizedList(new LinkedList<>());
    private static final List<byte[]> privateKeys = Collections.synchronizedList(new LinkedList<>());
    private static final List<Message> messages = Collections.synchronizedList(new LinkedList<>());

    public static void main(String[] args) throws IOException {
        ExecutorService threadPool = Executors.newCachedThreadPool();

        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(1155);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        while (true) {
            System.out.println("Ready for another.");
            Socket socket;
            try {
                socket = serverSocket.accept();
                System.out.println("Connected to " + socket.getInetAddress() + ":" + socket.getPort());
            } catch (IOException e) {
                e.printStackTrace();
                continue;
            }
            ServerThread thread = new ServerThread(socket, usernames, publicKeys, privateKeys, messages);
            threadPool.execute(thread);
        }
    }
}
