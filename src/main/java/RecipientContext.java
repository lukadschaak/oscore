/**
 * Used in CommonContext.
 * Created by Luka Dschaak on 23.03.2017.
 */
public class RecipientContext {

    private final byte[] recipientID;
    private final byte[] recipientKey; // symmetric key for decryption
    private final byte[] recipientIV;
    private byte[] maxSequenceNumber;
    private int slidingReplayWindow;

    RecipientContext(byte[] recipientID, byte[] recipientKey, byte[] recipientIV) {
        this.recipientID = recipientID;
        this.recipientKey = recipientKey;
        this.recipientIV = recipientIV;
        this.maxSequenceNumber = new byte[0];

        // last significant bit = lower edge
        // most significant bit = upper edge
        // so updating the sliding window is done with >>
        this.slidingReplayWindow = 0;
    }

    public byte[] getRecipientID() {
        return recipientID;
    }

    public byte[] getRecipientKey() {
        return recipientKey;
    }

    public byte[] getRecipientIV() {
        return recipientIV;
    }

    /**
     *
     * @param sequenceNumber
     * @return Returns false, if message was already processed or has to low sequence number. true
     * for the opposites.
     */
    public boolean compareReplayWindow(byte[] sequenceNumber) {

        int upperEdge = OscoapHelper.byteArrayToInt(this.maxSequenceNumber);
        int seqNumber = OscoapHelper.byteArrayToInt(sequenceNumber);

        if (seqNumber < 0) {
            return false;
        }

        int lowerEdge = upperEdge - 32 < 0 ? 0 : upperEdge - 32;

        if (seqNumber > upperEdge) {
            return true;
        } else if (seqNumber < lowerEdge) {
            return false;
        } else {
            // Compare the sequenceNumber with the state of the sliding window

            // check the requested bit position
            // example: upperEdge = 14223, seqNumber = 14219.
            // Then bitPosition would be 4.
            int bitPosition = upperEdge - seqNumber;

            // create a bit mask from the bitPosition
            // example: bitePosition = 4. bitMask would be 134.217.728, which is the 27th bit.
            int bitMask = 1 << (31 - bitPosition);

            // lets check if the bit is set or not
            boolean alreadyProcessed = (this.slidingReplayWindow & bitMask) != 0;

            if (alreadyProcessed) {
                return false;
            } else {
                return true;
            }
        }
    }

    public void updateReplayWindow(byte[] sequenceNumber) {

        int upperEdge = OscoapHelper.byteArrayToInt(this.maxSequenceNumber);
        int seqNumber = OscoapHelper.byteArrayToInt(sequenceNumber);

        if (seqNumber < 0) {
            return;
        }

        int lowerEdge = upperEdge - 32 < 0 ? 0 : upperEdge - 32;

        if (seqNumber > upperEdge) {
            int bitShifts = seqNumber - upperEdge;
            this.slidingReplayWindow = this.slidingReplayWindow >>> bitShifts;
            this.maxSequenceNumber = sequenceNumber;

            // set the highest bit to 1
            this.slidingReplayWindow = this.slidingReplayWindow | Integer.MIN_VALUE;
        } else if (seqNumber < lowerEdge) {
            // should never happen, because of compareReplayWindow
        } else {

            // update the sliding window

            // check the requested bit position
            // example: upperEdge = 14223, seqNumber = 14219.
            // Then bitPosition would be 4.
            int bitPosition = upperEdge - seqNumber;

            // create a bit mask from the bitPosition
            // example: bitPosition = 4. bitMask would be 134.217.728, which is the 27th bit.
            // Integer.toBinaryString(bitMask) = 0000 1000 0000 0000 0000 0000 0000 0000
            int bitMask = 1 << (31 - bitPosition);

            // lets check if the bit is set or not
            this.slidingReplayWindow = this.slidingReplayWindow | bitMask;
        }
    }
}
