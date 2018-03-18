import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;

/**
 * Created by Luka Dschaak
 *
 */
public class OscoapResource extends CoapResource {

    private boolean isProtected;

    OscoapResource(String name) {
        super(name);
        isProtected = true;
    }

    /**
     * Use int, because method signature with String, boolean is already used
     * @param name
     * @param isProtected
     */
    OscoapResource(String name, int isProtected) {
        super(name);
        if (isProtected == 0) {
            this.isProtected = false;
        } else {
            this.isProtected = true;
        }
    }

    @Override
    public void handleRequest(final Exchange exchange) {

        SecurityContextManager scm = SecurityContextManager.getInstance();
        boolean isProtectedMessage = scm.getSecurityContextByToken(exchange.getRequest().getToken()) != null;

        if (this.isProtected && !isProtectedMessage) {
            CoapExchange coapExchange = new CoapExchange(exchange, this);
            coapExchange.respond(CoAP.ResponseCode.UNAUTHORIZED);
            return;
        }

        if (!this.isProtected && isProtectedMessage) {
            CoapExchange coapExchange = new CoapExchange(exchange, this);
            coapExchange.respond(CoAP.ResponseCode.BAD_OPTION);
            return;
        }

        CoAP.Code code = exchange.getRequest().getCode();
        switch (code) {
            case GET: handleGET(new CoapExchange(exchange, this)); break;
            case POST: handlePOST(new CoapExchange(exchange, this)); break;
            case PUT: handlePUT(new CoapExchange(exchange, this)); break;
            case DELETE: handleDELETE(new CoapExchange(exchange, this)); break;
        }
    }

    @Override
    public synchronized void add(Resource child) {
        if (!(child instanceof OscoapResource)) {
            throw new NullPointerException("Child must be a OscoapResource also!");
        }
        super.add(child);
    }

    @Override
    public synchronized CoapResource add(CoapResource child) {
        if (!(child instanceof OscoapResource)) {
            throw new NullPointerException("Child must be a OscoapResource also!");
        }
        return super.add(child);
    }

    @Override
    public synchronized CoapResource add(CoapResource... children) {
        for (CoapResource child:children) {
            if (!(child instanceof OscoapResource)) {
                throw new NullPointerException("Child must be a OscoapResource also!");
            }
        }
        return super.add(children);
    }
}
