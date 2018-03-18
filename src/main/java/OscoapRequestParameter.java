/**
 * Created by Kidreo on 29.11.2017.
 * Stores the sequence number and the senderID from the request to
 * reuse them in a response.
 */
public class OscoapRequestParameter {

    private byte[] sequenceNumber;
    private byte[] requestID;

    public OscoapRequestParameter(byte[] sequnceNumber, byte[] requestID) {
        this.sequenceNumber = new byte[sequnceNumber.length];
        System.arraycopy(sequnceNumber, 0, this.sequenceNumber, 0, sequnceNumber.length);
        this.requestID = requestID;
    }

    public byte[] getSequenceNumber() {
        return sequenceNumber;
    }

    public byte[] getRequestID() {
        return requestID;
    }
}
