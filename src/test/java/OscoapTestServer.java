import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.server.resources.CoapExchange;

import java.net.*;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import static java.lang.System.exit;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.*;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

/**
 *
 * Created by Luka Dschaak on 12.07.2017.
 */
public class OscoapTestServer extends CoapServer {

    public static void main(String[] args) {

        String hostString = "";
        String foreignHostString = "";

        if (args.length == 0 || args.length > 2) {
            String helpMessage = "" +
                    "This is OscoapTestClient. Usage:\n" +
                    "First argument: Opponents address\n" +
                    "Second argument (optional): Own address.\n" +
                    "If there is no second argument, Java will try to find\n" +
                    "out the ip address of this machine itself.\n" +
                    "Addresses are also important for security contexts!\n";
            System.out.println(helpMessage);
            exit(0);
        }


        if (args.length == 1) {
            foreignHostString = args[0];

            InetAddress inetAddress;
            try {
                inetAddress = InetAddress.getLocalHost();
                hostString = inetAddress.getHostAddress();
            } catch (UnknownHostException | NullPointerException e) {
                System.out.println("ERROR: Could not determine your own IP address. Please \n" +
                        "restart with two arguments (first: address of this machine).");
            }
            System.out.println("Java says the address of this machine is: "+ hostString);
            System.out.println("If this is wrong, rerun with two arguments!");
        }

        if (args.length == 2) {
            foreignHostString = args[0];
            hostString = args[1];
        }

        URI host = null;
        URI foreignHost = null;

        if (!foreignHostString.contains("//")) {
            foreignHostString = "//"+foreignHostString;
        }
        if (!hostString.contains("//")) {
            hostString = "//"+hostString;
        }

        try{
            foreignHost = new URI(foreignHostString);
            if (foreignHost.getPort() == -1) {
                foreignHost = new URI(foreignHostString +":"+ CoAP.DEFAULT_COAP_PORT);
            }

            host = new URI(hostString);
            if (host.getPort() == -1) {
                host = new URI(hostString +":"+ CoAP.DEFAULT_COAP_PORT);
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
            System.out.println("Error: One of the addresses is malformed.");
            exit(0);
        }

        try {
            // create debug security contexts for server
            SecurityContextManager scm = SecurityContextManager.getInstance();

            scm.addSecurityContext(OscoapHelper
                    .getSecurityContextForServerDefault(foreignHost.getHost()));

            // create server
            OscoapTestServer server = new OscoapTestServer();

            InetSocketAddress bindToAddress = new InetSocketAddress(host.getHost(), host.getPort());
            OscoapEndpoint oscoapEndpoint = new OscoapEndpoint(bindToAddress);
            server.addEndpoint(oscoapEndpoint);

            server.start();

        } catch (SocketException e) {
            System.err.println("Failed to initialize server: " + e.getMessage());
            e.printStackTrace();
        }

    }

    private OscoapTestServer() throws SocketException {

        OscoapResource resource = new HelloResource();
        resource.add(new HelloCoapResource());
        resource.add(new Hello1Resource());
        resource.add(new Hello2Resource());
        resource.add(new Hello3Resource());
        resource.add(new Hello6Resource());
        resource.add(new Hello7Resource());
        add(resource);

        add(new ObservableResource());
        add(new TestResource());
        add(new LargeResource());
    }

    /**
     * The /hello Root resource for the tests
     */
    class HelloResource extends OscoapResource {
        private HelloResource() {
            super("hello");
            getAttributes().setTitle("Just the parent");
        }
    }

    /**
     * The unprotected /hello/coap resource
     */
    class HelloCoapResource extends OscoapResource {
        private HelloCoapResource() {
            super("coap", 0);
            getAttributes().setTitle("Hello-World Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond("Hello World!");
        }
    }

    /**
     * The /hello/1 resource
     */
    class Hello1Resource extends OscoapResource {
        private Hello1Resource() {
            super("1");
            getAttributes().setTitle("Hello-World 1 Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond("Hello World!");
        }
    }

    /**
     * the /hello/2 resource
     * Only response with ETag, when QueryList contains "first=1"
     */
    class Hello2Resource extends OscoapResource {
        private Hello2Resource() {
            super("2");
            getAttributes().setTitle("Hello-World 2 Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            List<String> uriQueryList = exchange.getRequestOptions().getUriQuery();
            if (uriQueryList.size() == 1) {
                if (uriQueryList.get(0).equals("first=1")) {
                    exchange.setETag(new byte[]{43}); // 0x2b
                }
            }

            exchange.respond("Hello World!");
        }
    }

    /**
     * The /hello/3 resource.
     * Response content, if accept == 0, else Bad Option
     */
    class Hello3Resource extends OscoapResource {
        private Hello3Resource() {
            super("3");
            getAttributes().setTitle("Hello-World 3 Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            if (exchange.getRequestOptions().getAccept() == 0 ) {
                exchange.setMaxAge(0x05);
                exchange.respond("Hello World!");
            } else {
                exchange.respond(CoAP.ResponseCode.BAD_OPTION);
            }
        }
    }

    /**
     * The /hello/6 resource
     * Provides GET and POST
     */
    class Hello6Resource extends OscoapResource {
        private String value;
        private Hello6Resource() {
            super("6");
            value = "Hello World!";
            getAttributes().setTitle("Hello-World 6 Resource");
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond(value);
        }

        @Override
        public void handlePOST(CoapExchange exchange) {
            byte[] payload = exchange.getRequestPayload();
            if (payload.length == 1 && payload[0] == 74) { // 74 = 0x4a
                value = exchange.getRequestText();
                exchange.respond(CHANGED);
            } else {
                exchange.respond(CoAP.ResponseCode.BAD_OPTION);
            }
        }
    }

    /**
     * The /hello/7 resource
     * Provides GET and PUT
     */
    class Hello7Resource extends OscoapResource {
        private String value;
        private Hello7Resource() {
            super("7");
            value = "Hello World!";
            getAttributes().setTitle("Hello-World 7 Resource for PUT Test");
            setVisible(false);
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond(value);
        }

        @Override
        public void handlePUT(CoapExchange exchange) {
            if (exchange.getRequestOptions().hasIfNoneMatch()) {
                exchange.respond(PRECONDITION_FAILED);

                // automatically reset
                value = null;
            } else {
                boolean fullfilled = false;
                List<byte[]> ifMatchList = exchange.getRequestOptions().getIfMatch();
                for (byte[] value : ifMatchList) {
                    if (value.length == 1 && value[0] == 123) { // 0x7b
                        fullfilled = true;
                    }
                }
                if (fullfilled) {
                    value = exchange.getRequestText();
                    setVisible(true);
                    changed();
                    exchange.respond(CHANGED);
                } else {
                    exchange.respond(BAD_REQUEST, "if Match not fitting");
                }
            }
        }
    }

    /**
     * The /test resource
     * For DELETE test
     */
    class TestResource extends OscoapResource {
        private TestResource() {
            super("test");
            getAttributes().setTitle("Test Resource");
        }

        @Override
        public void handleDELETE(CoapExchange exchange) {
            exchange.respond(CoAP.ResponseCode.DELETED);
        }
    }

    /**
     * The /observe resource for test 5
     */
    class ObservableResource extends OscoapResource {

        private int counter;

        private ObservableResource() {
            super("observe");
            getAttributes().setTitle("Observe Resource");

            counter = 0;

            setObservable(true);
            setObserveType(CoAP.Type.CON);
            getAttributes().setObservable();

            Timer timer = new Timer();
            timer.schedule(new UpdateTask(), 0, 2000);
        }

        private class UpdateTask extends TimerTask {
            @Override
            public void run() {
                counter++;
                changed();
            }
        }

        @Override
        public void handleGET(CoapExchange exchange) {
            exchange.respond("Counter: "+counter);
        }
    }

    class LargeResource extends OscoapResource {

        public LargeResource() {
            super("large");
            getAttributes().setTitle("Large resource");
            getAttributes().addResourceType("block");
            getAttributes().setMaximumSizeEstimate(1280);
        }

        @Override
        public void handleGET(CoapExchange exchange) {

            StringBuilder builder = new StringBuilder();
            builder.append("/-------------------------------------------------------------\\\n");
            builder.append("|                 RESOURCE BLOCK NO. 1 OF 5                   |\n");
            builder.append("|               [each line contains 64 bytes]                 |\n");
            builder.append("\\-------------------------------------------------------------/\n");
            builder.append("/-------------------------------------------------------------\\\n");
            builder.append("|                 RESOURCE BLOCK NO. 2 OF 5                   |\n");
            builder.append("|               [each line contains 64 bytes]                 |\n");
            builder.append("\\-------------------------------------------------------------/\n");
            builder.append("/-------------------------------------------------------------\\\n");
            builder.append("|                 RESOURCE BLOCK NO. 3 OF 5                   |\n");
            builder.append("|               [each line contains 64 bytes]                 |\n");
            builder.append("\\-------------------------------------------------------------/\n");
            builder.append("/-------------------------------------------------------------\\\n");
            builder.append("|                 RESOURCE BLOCK NO. 4 OF 5                   |\n");
            builder.append("|               [each line contains 64 bytes]                 |\n");
            builder.append("\\-------------------------------------------------------------/\n");
            builder.append("/-------------------------------------------------------------\\\n");
            builder.append("|                 RESOURCE BLOCK NO. 5 OF 5                   |\n");
            builder.append("|               [each line contains 64 bytes]                 |\n");
            builder.append("\\-------------------------------------------------------------/\n");

            exchange.respond(CONTENT, builder.toString(), TEXT_PLAIN);
        }
    }
}
