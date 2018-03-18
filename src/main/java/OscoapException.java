import org.eclipse.californium.core.coap.CoAP;

/**
 * Created by Luka Dschaak on 03.08.2017.
 */
public class OscoapException extends Exception {

    public static final int SEND_NOTHING = 0;
    public static final int SEND_EMPTY = 1;
    public static final int SEND_RESPONSE = 2;

    private int sendBehaviour;

    private CoAP.Type type;

    private CoAP.ResponseCode code;

    OscoapException(String message, int sendBehaviour, CoAP.Type type, CoAP.ResponseCode code) {
        super(message);
        this.sendBehaviour = sendBehaviour;
        this.type = type;
        this.code = code;
    }

    public int getSendBehaviour() {
        return sendBehaviour;
    }

    public CoAP.Type getType() {
        return type;
    }

    public CoAP.ResponseCode getCode() {
        return code;
    }
}
