public class Message {
    public final byte authorID;
    public final byte recipientID;
    public final byte[] message;

    public Message(byte authorID, byte recipientID, byte[] message) {
        this.authorID = authorID;
        this.recipientID = recipientID;
        this.message = message;
    }
}
