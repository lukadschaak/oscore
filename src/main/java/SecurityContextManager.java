import org.eclipse.californium.core.coap.Request;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * Created by Luka Dschaak on 26.07.2017.
 */
public class SecurityContextManager {

    private static SecurityContextManager instance = null;

    private List<CommonContext> securityContexts;

    private List<Request> sendUnsecured;

    protected SecurityContextManager() {
        this.securityContexts = new LinkedList<>();
        this.sendUnsecured = new LinkedList<>();
    }

    public static SecurityContextManager getInstance() {
        if(instance == null) {
            instance = new SecurityContextManager();
        }
        return instance;
    }

    /**
     * Overloaded method. Calls same method with string
     * @param uri parsed to string
     * @return
     */
    public CommonContext getSecurityContextByHost(URI uri) {
        String host = uri.getHost();
        return this.getSecurityContextByHost(host);
    }

    /**
     * Returns the security context fitting to the host of the uri
     * @param host as string
     * @return the security context
     */
    public CommonContext getSecurityContextByHost(String host) {
        host = OscoapHelper.reducedIPv6Host(host);
        for( CommonContext context : this.securityContexts ) {
            if (context.getTargetResourceHost().equals(host)) {
                return context;
            }
        }

        return null;
    }

    /**
     * Returns the security context fitting to the senderID
     * @param senderID the sender id as byte[]
     * @return the security context
     */
    public CommonContext getSecurityContextByID(byte[] senderID) {
        for( CommonContext context : this.securityContexts ) {
            if (Arrays.equals(context.getRecipientContext().getRecipientID(), senderID)) {
                return context;
            }
        }

        return null;
    }

    /**
     * Returns the security context fitting to the token of the current message
     * @param requestToken the token of the current message
     * @return the security context
     */
    public CommonContext getSecurityContextByToken(byte[] requestToken) {
        for( CommonContext context : this.securityContexts ) {
            if (context.hasCurrentToken(requestToken)) {
                return context;
            }
        }

        return null;
    }

    public void addSecurityContext(CommonContext commonContext) {
        this.securityContexts.add(commonContext);
    }

    public void removeSecurityContext(CommonContext commonContext) {
        this.securityContexts.remove(commonContext);
    }

    public void sendUnsecured(Request request) {
        sendUnsecured.add(request);
    }

    public boolean shallBeUnsecured(Request request) {
        if (sendUnsecured.contains(request)) {
            sendUnsecured.remove(request);
            return true;
        }
        return false;
    }
}
