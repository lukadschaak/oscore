import COSE.AlgorithmID;

import java.util.ArrayList;
import java.util.HashMap;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

/**
 * Common Context build the context for an endpoint for communication with another endpoint.
 * Reference a SenderContext and a RecipientContext
 * Created by Luka Dschaak on 23.03.2017.
 */
public class CommonContext {

    // All final, because they are immutable values
    private final AlgorithmID algorithm; // "AES-CCM-64-64-128" is mandatory 26 in COSE
    private final byte[] masterSecret;
    private final byte[] masterSalt;

    private SenderContext senderContext;
    private RecipientContext recipientContext;

    private final String targetResourceHost;

    // String = Token, OscoapRequest = (sequnceNumber, senderID)
    private HashMap<String, OscoapRequestParameter> requestList;


    CommonContext(AlgorithmID algorithm, byte[] masterSecret, byte[] masterSalt, String targetResourceHost){
        this.algorithm = algorithm;
        this.masterSecret = masterSecret;
        this.masterSalt = masterSalt;
        this.targetResourceHost = OscoapHelper.reducedIPv6Host(targetResourceHost);
        this.requestList = new HashMap<>();
    }

    public AlgorithmID getAlgorithm() {
        return algorithm;
    }

    public byte[] getMasterSecret() {
        return masterSecret;
    }

    public byte[] getMasterSalt() {
        return masterSalt;
    }

    public SenderContext getSenderContext() {
        return senderContext;
    }

    void setSenderContext(SenderContext senderContext) {
        this.senderContext = senderContext;
    }

    public RecipientContext getRecipientContext() {
        return recipientContext;
    }

    void setRecipientContext(RecipientContext recipientContext) {
        this.recipientContext = recipientContext;
    }

    public String getTargetResourceHost() {
        return targetResourceHost;
    }

    public boolean hasCurrentToken(byte[] requestToken) {
        String tokenString = printHexBinary(requestToken);
        return this.requestList.containsKey(tokenString);
    }

    public void addRequestParameters(byte[] token, OscoapRequestParameter params) {
        String tokenString = printHexBinary(token);
        this.requestList.put(tokenString, params);
    }

    public OscoapRequestParameter getAndRemoveRequestParameters(byte[] token) {
        String tokenString = printHexBinary(token);
        return requestList.remove(tokenString);
    }
}
