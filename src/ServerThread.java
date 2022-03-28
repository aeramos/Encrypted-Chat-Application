import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class ServerThread implements Runnable {
    private final Socket socket;
    private final InputStream socketInput;
    private final OutputStream socketOutput;
    private final List<String> usernames;
    private final List<PublicKey> publicKeys;
    private final List<Message> messages;

    private byte id = -1;

    public ServerThread(Socket socket, List<String> usernames, List<PublicKey> publicKeys, List<Message> messages) throws IOException {
        this.socket = socket;
        this.socketInput = socket.getInputStream();
        this.socketOutput = socket.getOutputStream();
        this.usernames = usernames;
        this.publicKeys = publicKeys;
        this.messages = messages;
    }

    @Override
    public void run() {
        while (socket.isConnected()) {
            byte[] input = new byte[3];
            try {
                socketInput.readNBytes(input, 0, 3);
                String command = "" + (char)(input[0]) + (char)(input[1]) + (char)(input[2]);
                switch (command) {
                    case "SET":
                        input = socketInput.readNBytes(16);
                        String username = "";
                        for (int i = 0; i < 16; i++) {
                            if (input[i] == 0) {
                                break;
                            }
                            username += (char)input[i];
                        }
                        byte[] key = socketInput.readNBytes(550);
                        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
                        int index = publicKeys.indexOf(publicKey);
                        if (index == -1) {
                            publicKeys.add(publicKey);
                            usernames.add(username);
                            index = publicKeys.size() - 1;
                        } else {
                            usernames.set(index, username);
                        }
                        this.id = (byte)index;
                        socketOutput.write(new byte[] {'S', 'E', 'T', (byte)index});
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
                        index = socketInput.readNBytes(1)[0];
                        input = new byte[3 + 1 + 550];
                        input[0] = 'P';
                        input[1] = 'U';
                        input[2] = 'B';
                        input[3] = (byte)index;
                        System.arraycopy(publicKeys.get(index).getEncoded(), 0, input, 4, 550);
                        socketOutput.write(input);
                        break;
                    case "MSG":
                        byte recipientID = socketInput.readNBytes(1)[0];
                        this.messages.add(new Message(this.id, recipientID, socketInput.readNBytes(512 + (16 * socketInput.readNBytes(1)[0]))));
                        break;
                    case "GET":
                        byte authorID = socketInput.readNBytes(1)[0];
                        int requestedNumber = socketInput.readNBytes(1)[0];
                        int responseLength = 3 + 1 + 1;
                        ArrayList<Message> requestedMessages = new ArrayList<>(requestedNumber);
                        for (int i = this.messages.size() - 1; i >= 0; i--) {
                            Message message = this.messages.get(i);
                            if (message.authorID == authorID && message.recipientID == this.id) {
                                requestedMessages.add(message);
                                responseLength += 1 + message.message.length;
                            }
                            if (requestedMessages.size() == requestedNumber) {
                                break;
                            }
                        }
                        input = new byte[responseLength];
                        input[0] = 'G';
                        input[1] = 'E';
                        input[2] = 'T';
                        input[3] = authorID;
                        input[4] = (byte)requestedMessages.size();
                        int pointer = 5;
                        for (int i = requestedMessages.size() - 1; i >= 0; i--) {
                            Message message = requestedMessages.get(i);
                            byte[] msg = message.message;
                            input[pointer++] = (byte)((msg.length - 512) / 16);
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
}
