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
