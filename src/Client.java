import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class Client {
    enum OutputMode {
        MSG, GET, CMD, SET, BYE, LST, PUB, LOG
    }

    private final Socket socket;
    private final InputStream socketInput;
    private final OutputStream socketOutput;
    private final Map<Byte, PublicKey> publicKeys;
    private byte id;
    private OutputMode mode;
    private final Scanner scanner;
    private KeyPair keyPair;

    public static void main(String... args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        Socket socket;
        try {
            socket = new Socket("localhost", 1155);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }
        Client client;
        try {
            client = new Client(socket);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error initializing client. Goodbye.");
            return;
        }
        client.run();
    }

    public Client(Socket socket) throws IOException {
        this.socket = socket;
        this.socketInput = socket.getInputStream();
        this.socketOutput = socket.getOutputStream();
        this.publicKeys = new HashMap<>();
        this.id = -1;
        this.mode = OutputMode.LOG;
        this.scanner = new Scanner(System.in);
    }

    public void run() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        System.out.println("Connected to server.\nEnter \\quit to disconnect at any time.");

        String input;
        byte[] output;
        while (this.socket.isConnected()) {
            switch (mode) {
                case SET:
                        System.out.println("Desired username (1-16 characters): ");
                        input = scanner.nextLine();
                        if (modeSwitched(input)) {
                            continue;
                        }
                        if (input.length() > 16 || input.length() == 0) {
                            System.out.println("Invalid length. Please try again.");
                        } else if (input.startsWith("\\")) {
                            System.out.println("Username can not start with \\. Please try again");
                        } else {
                            set(input);
                            output = this.socketInput.readNBytes(4);
                            if (output[0] == 'S') {
                                this.id = output[3];
                                this.mode = OutputMode.CMD;
                            } else {
                                System.out.println("Something went wrong. Please try again.");
                            }
                        }
                    break;
                case LOG:
                    System.out.println("Username: ");
                    String username = scanner.nextLine();
                    if (modeSwitched(username)) {
                        continue;
                    }
                    if (username.length() > 16 || username.length() == 0) {
                        System.out.println("Invalid length. Please try again.");
                    } else if (username.startsWith("\\")) {
                        System.out.println("Username can not start with \\. Please try again");
                    } else {
                        log(username);

                        System.out.println("Password: ");
                        input = scanner.nextLine();
                        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                        SecretKeySpec aesKey = new SecretKeySpec(sha256.digest(input.getBytes(StandardCharsets.US_ASCII)), "AES");

                        output = this.socketInput.readNBytes(4);
                        if (output[3] == 'Y') {
                            this.id = this.socketInput.readNBytes(1)[0];
                            byte[] publicKey = this.socketInput.readNBytes(550);
                            byte[] privateKey = this.socketInput.readNBytes(2384);
                            setKeyPair(publicKey, decryptAES(privateKey, aesKey));
                            this.mode = OutputMode.CMD;

                            output = this.socketInput.readNBytes(8);
                            byte[] signedTimestamp = signRSA(output, this.keyPair.getPrivate());
                            output = new byte[3 + 1 + signedTimestamp.length];
                            output[0] = 'L';
                            output[1] = 'O';
                            output[2] = 'G';
                            output[3] = 'B';
                            System.arraycopy(signedTimestamp, 0, output, 4, signedTimestamp.length);
                            this.socketOutput.write(output);
                            if (this.socketInput.readNBytes(4)[3] == 'S') {
                                System.out.println("Logged in successfully! You can now send and receive encrypted messages.");
                            }
                        } else {
                            System.out.println("No information found for this username.");
                            System.out.println("Would you like to make an account (Y) or try again (N)?");
                            input = scanner.nextLine();
                            if (input.equals("Y")) {
                                reg(username, aesKey);
                                output = this.socketInput.readNBytes(4);
                                this.id = output[3];
                                this.mode = OutputMode.CMD;
                            }
                        }
                    }
                    break;
                case CMD:
                    System.out.println("Please select a command: \\GET, \\LST, \\MSG, \\PUB, \\SET, or \\QUIT");
                    input = scanner.nextLine();
                    if (!modeSwitched(input)) {
                        System.out.println("Invalid input. Please try again.");
                    }
                    break;
                case LST:
                    System.out.println("Requesting list of users from the server.");
                    lst();
                    output = this.socketInput.readNBytes(3);
                    if (output[0] == 'L') {
                        int len = this.socketInput.readNBytes(1)[0] * 17;
                        output = this.socketInput.readNBytes(len);
                        for (int i = 0; i < output.length / 17; i++) {
                            System.out.print("(" + output[i * 17] + ") ");
                            byte[] usrName = new byte[16];
                            System.arraycopy(output, i * 17 + 1, usrName, 0, 16);
                            for (final byte letter : usrName) {
                                if (letter != 0) {
                                    System.out.print((char)letter);
                                }
                            }
                            System.out.println();
                        }
                        mode = OutputMode.CMD;
                    } else {
                        System.out.println("Something went wrong. Trying again.");
                    }
                    break;
                case PUB:
                    System.out.println("Enter the ID of the user whose public key you want:");
                    input = scanner.nextLine();
                    if (modeSwitched(input)) {
                        continue;
                    }
                    pub(Byte.parseByte(input));
                    output = this.socketInput.readNBytes(3 + 1 + 550);
                    byte[] key = new byte[550];
                    System.arraycopy(output, 4, key, 0, 550);
                    try {
                        publicKeys.put(Byte.parseByte(input), KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key)));
                        mode = OutputMode.CMD;
                    } catch (Exception e) {
                        e.printStackTrace();
                        System.out.println("Something went wrong. Please try again.");
                    }
                    break;
                case MSG:
                    System.out.println("Enter the recipient's ID:");
                    input = scanner.nextLine();
                    if (modeSwitched(input)) {
                        continue;
                    }
                    byte id = Byte.parseByte(input);
                    System.out.println("Enter your message: ");
                    input = scanner.nextLine();
                    if (modeSwitched(input)) {
                        continue;
                    }
                    msg(id, input);
                    break;
                case GET:
                    System.out.println("Enter the author's ID:");
                    input = scanner.nextLine();
                    if (modeSwitched(input)) {
                        continue;
                    }
                    id = Byte.parseByte(input);
                    System.out.println("Getting last 10 messages.");
                    get(id, (byte)10);
                    int numberOfMessages = socketInput.readNBytes(5)[4];
                    for (int i = 0; i < numberOfMessages; i++) {
                        byte[] message = socketInput.readNBytes(512 + socketInput.readNBytes(1)[0] * 16);
                        System.out.println(getMessage(message));
                    }
                    mode = OutputMode.CMD;
                    break;
                case BYE:
                    System.out.println("Disconnecting from server.");
                    scanner.close();
                    socket.close();
                    break;
            }
        }
        System.out.println("Disconnected from server. Shutting down.");
    }

    private void setKeyPair(byte[] publicKeyBytes, byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publickey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privatekey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        this.keyPair = new KeyPair(publickey, privatekey);
    }

    private String getMessage(byte[] encryptedMessage) {
        return decodeMsg(encryptedMessage, this.keyPair.getPrivate());
    }

    private String[] getMessages(byte[] data) {
        byte numberOfMessages = data[3];
        String[] messages = new String[numberOfMessages];
        int startPoint = 4;
        for (int i = 0; i < numberOfMessages; i++) {
            byte numberOfAesBlocks = data[startPoint];
            byte[] encryptedMessage = new byte[512 + (numberOfAesBlocks * 16)];
            System.arraycopy(data, startPoint + 1, encryptedMessage, 0, 512 + (numberOfAesBlocks * 16));

            messages[i] = decodeMsg(encryptedMessage, this.keyPair.getPrivate());
            startPoint += 512 + (numberOfAesBlocks * 16) + 1;
        }
        return messages;
    }

    private void get(byte authorID, byte numberToGet) throws IOException {
        socketOutput.write(new byte[] {'G', 'E', 'T', authorID, numberToGet});
    }

    private void msg(byte recipientID, String message) throws IOException {
        Cipher cipher;
        byte[] encryptedKey;
        SecretKey aesKey = generateKey();
        byte[] encryptedMessage;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKeys.get(recipientID));
            encryptedKey = cipher.doFinal(aesKey.getEncoded());

            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            encryptedMessage = cipher.doFinal(message.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
        byte[] output = new byte[3 + 1 + 1 + encryptedKey.length + encryptedMessage.length];
        output[0] = 'M';
        output[1] = 'S';
        output[2] = 'G';
        output[3] = recipientID;
        output[4] = (byte)(encryptedMessage.length / 16);
        System.arraycopy(encryptedKey, 0, output, 5, encryptedKey.length);
        System.arraycopy(encryptedMessage, 0, output, 5 + encryptedKey.length, encryptedMessage.length);
        socketOutput.write(output);
    }

    private void pub(byte id) throws IOException {
        socketOutput.write(new byte[] {'P', 'U', 'B', id});
    }

    private void lst() throws IOException {
        socketOutput.write(new byte[] {'L', 'S', 'T'});
    }

    private void reg(String username, SecretKey aesKey) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator generator;
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(4096);
        this.keyPair = generator.generateKeyPair();
        byte[] encryptedPrivate = encryptAES(keyPair.getPrivate().getEncoded(), aesKey);
        byte[] output = new byte[3 + 16 + 550 + encryptedPrivate.length];
        output[0] = 'R';
        output[1] = 'E';
        output[2] = 'G';
        System.arraycopy(username.getBytes(StandardCharsets.US_ASCII), 0, output, 3, username.length());
        System.arraycopy(this.keyPair.getPublic().getEncoded(), 0, output, 3 + 16, 550);
        System.arraycopy(encryptedPrivate, 0, output, 3 + 16 + 550, encryptedPrivate.length);
        socketOutput.write(output);
    }

    private void log(String username) throws IOException {
        byte[] output = new byte[4 + 16];
        output[0] = 'L';
        output[1] = 'O';
        output[2] = 'G';
        output[3] = 'A';
        System.arraycopy(username.getBytes(StandardCharsets.US_ASCII), 0, output, 4, username.length());
        socketOutput.write(output);
    }

    private void set(String username) throws IOException {
        byte[] output = new byte[3 + 16 + 550];
        output[0] = 'S';
        output[1] = 'E';
        output[2] = 'T';
        System.arraycopy(username.getBytes(StandardCharsets.US_ASCII), 0, output, 3, username.length());
        System.arraycopy(this.keyPair.getPublic().getEncoded(), 0, output, 3 + 16, 550);
        socketOutput.write(output);
    }

    private boolean modeSwitched(String input) {
        if (input.equals("\\QUIT")) {
            mode = OutputMode.BYE;
            return true;
        }
        switch (input) {
            case "\\LST":
                mode = OutputMode.LST;
                break;
            case "\\GET":
                mode = OutputMode.GET;
                break;
            case "\\MSG":
                mode = OutputMode.MSG;
                break;
            case "\\PUB":
                mode = OutputMode.PUB;
                break;
            case "\\SET":
                mode = OutputMode.SET;
                break;
            default:
                return false;
        }
        return true;
    }

    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static String decodeMsg(byte[] msg, PrivateKey key) {
        Cipher cipher;
        String message;
        try {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] encryptedKey = new byte[512];
            System.arraycopy(msg, 0, encryptedKey, 0, 512);
            byte[] aesKey = cipher.doFinal(encryptedKey);

            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"));
            byte[] encryptedMessage = new byte[msg.length - 512];
            System.arraycopy(msg, 512, encryptedMessage, 0, msg.length - 512);
            message = new String(cipher.doFinal(encryptedMessage), StandardCharsets.US_ASCII);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return message;
    }

    private static byte[] signRSA(byte[] input, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    private static byte[] encryptAES(byte[] msg, SecretKey key) {
        Cipher cipher;
        byte[] message;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            message = cipher.doFinal(msg);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return message;
    }

    private static byte[] decryptAES(byte[] msg, SecretKey key) {
        Cipher cipher;
        byte[] message;
        try {
            cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            message = cipher.doFinal(msg);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
        return message;
    }

    private static SecretKey generateKey() {
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
}
