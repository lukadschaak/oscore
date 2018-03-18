/**
 * Used in CommonContext.
 * Created by Luka Dschaak on 23.03.2017.
 */
public class SenderContext {

    private final byte[] senderID;
    private final byte[] senderKey; // symmetric key for encryption
    private final byte[] senderIV;
    private byte[] sequenceNumber;

    SenderContext(byte[] senderID, byte[] senderKey, byte[] senderIV) {
        this.senderID = senderID;
        this.senderKey = senderKey;
        this.senderIV = senderIV;
        this.sequenceNumber = new byte[]{0};
    }

    byte[] getSenderID() {
        return senderID;
    }

    public byte[] getSenderKey() {
        return senderKey;
    }

    public byte[] getSenderIV() {
        return senderIV;
    }

    public byte[] getSequenceNumber() {
        return sequenceNumber;
    }

    public void incrementSequenceNumber() {
        byte last = sequenceNumber[sequenceNumber.length-1];

        if ((last & 0xFF) == 255) {
            byte[] newSequenceNumber = new byte[sequenceNumber.length+1];
            System.arraycopy(sequenceNumber, 0, newSequenceNumber, 0, sequenceNumber.length);
            newSequenceNumber[sequenceNumber.length-1] = (byte) 0;
            newSequenceNumber[sequenceNumber.length] = (byte) 1;
            sequenceNumber = newSequenceNumber;
        } else {
            sequenceNumber[sequenceNumber.length-1] = (byte) ((int)last + 1);
        }
    }

    public SenderContext setSequenceNumber(byte[] sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
        return this;
    }
}
