import org.eclipse.californium.core.*;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.lang.System.exit;

/**
 *
 * Created by Luka Dschaak on 12.07.2017.
 */
public class OscoapTestClient {

    private final static Logger LOGGER = Logger.getLogger(OscoapTestClient.class.getCanonicalName());

    private CoapClient client;
    private URI host;
    private URI foreignHost;
    private String baseTestUri;

    private static int maxTests = 16;

    public static void main(String[] args) {

        OscoapTestClient testClient = new OscoapTestClient();

        String host = "";
        String foreignHost = "";

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
            foreignHost = args[0];

            InetAddress inetAddress;
            try {
                inetAddress = InetAddress.getLocalHost();
                host = inetAddress.getHostAddress();
            } catch (UnknownHostException | NullPointerException e) {
                System.out.println("ERROR: Could not determine your own IP address. Please \n" +
                        "restart with two arguments (first: address of this machine).");
            }
            System.out.println("Java says the address of this machine is: "+ testClient.host);
            System.out.println("If this is wrong, rerun with two arguments!");
        }

        if (args.length == 2) {
            foreignHost = args[0];
            host = args[1];
        }

        String helloMessage = "\n" +
                "This is a test client for OSCOAP\n" +
                "This client is able to run "+ maxTests +" different tests in current version\n" +
                "The client is build upon californium and was created by Luka Dschaak\n" +
                "--\n";
        System.out.println(helloMessage);


        if (!foreignHost.contains("//")) {
            foreignHost = "//"+foreignHost;
        }
        if (!host.contains("//")) {
            host = "//"+host;
        }

        try{
            testClient.foreignHost = new URI(foreignHost);
            if (testClient.foreignHost.getPort() == -1) {
                testClient.foreignHost = new URI(foreignHost +":"+ CoAP.DEFAULT_COAP_PORT);
            }

            testClient.host = new URI(host);
            if (testClient.host.getPort() == -1) {
                testClient.host = new URI(host +":"+ CoAP.DEFAULT_COAP_PORT);
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
            System.out.println("Error: One of the addresses is malformed.");
            exit(0);
        }

        testClient.baseTestUri = "coap://"+ testClient.foreignHost.getHost() +
                ":"+ testClient.foreignHost.getPort();
        testClient.client = new CoapClient(testClient.baseTestUri);

        InetSocketAddress address = new InetSocketAddress(
                testClient.host.getHost(), testClient.host.getPort());
        OscoapEndpoint endpoint = new OscoapEndpoint(address);

        try {
            endpoint.start();
            LOGGER.log(Level.INFO, "Created implicit OSCOAP endpoint {0}", endpoint.getAddress());
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Could not create OSCOAP endpoint", e);
        }

        testClient.client.setEndpoint(endpoint);


        // does not work, don't know why
//        testClient.client.getEndpoint().getConfig().set("MAX_RETRANSMIT", 0);

        // try to perform a ping. Its done with changing the californium properties
        System.out.println("INFO: A ping is done before testing can be started");
        CoapClient unsecuredTestClient = new CoapClient(testClient.baseTestUri);

        boolean ping = unsecuredTestClient.ping();
        if (!ping) {
            System.out.println("SEVERE: Ping was not successful. Start or check the server and restart this client.");
            exit(0);
        } else {
            System.out.println("INFO: Ping is OK. Continue.");
        }

        testClient.runTests();
    }

    private void runTests() {
        // later the tests can manipulate the context states
        SecurityContextManager scm = SecurityContextManager.getInstance();
        scm.addSecurityContext(
                OscoapHelper.getSecurityContextForClientDefault(this.foreignHost.getHost()));

        boolean keepRunning = true;
        int nextTest = 0;

        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        while( keepRunning ) {
            try {
                System.out.println();
                System.out.println();
                System.out.println("Please choose your option.");
                if (nextTest > maxTests) {
                    nextTest = maxTests;
                }
                System.out.println("\"n\": next test (would be "+ nextTest +"); [number]: test number; \"all\": all tests; \"exit\": terminate");
                String line = br.readLine();

                if ( line.equals("n") ) {
                    runSpecificTest(nextTest);
                    nextTest++;
                } else if (line.equals("exit")) {
                    System.out.println("Good bye, Thanks for testing!");
                    keepRunning = false;
                    exit(0);
                } else if (line.equals("all")) {
                    runAllTests();
                } else if (OscoapHelper.isInteger(line)) {
                    int wantedTest = Integer.parseInt(line);
                    if (wantedTest > maxTests) {
                        System.out.println("Sorry. There are only "+ maxTests +" tests, please choose another test or restart.");
                    } else {
                        nextTest = wantedTest + 1;
                        runSpecificTest(wantedTest);
                    }
                } else {
                    System.out.println("This is not a valid Option!");
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void debugPrintResponse(CoapResponse response) {
        if (response!=null) {

            System.out.println(response.getCode());
            System.out.println(response.getOptions());
            System.out.println(response.getResponseText());

            System.out.println(System.lineSeparator() + "ADVANCED" + System.lineSeparator());
            // access advanced API with access to more details through
            // .advanced()
            System.out.println(Utils.prettyPrint(response));
        } else {
            System.out.println("No response received.");
        }
    }

    private void setDefaultSecurityContext() {
        SecurityContextManager scm = SecurityContextManager.getInstance();
        CommonContext cc = scm.getSecurityContextByHost(this.foreignHost);
        byte[] sequenceNumber = cc.getSenderContext().getSequenceNumber();

        CommonContext testContext = OscoapHelper
                .getSecurityContextForClientDefault(this.foreignHost.getHost());
        testContext.getSenderContext().setSequenceNumber(sequenceNumber);

        scm.removeSecurityContext(cc);
        scm.addSecurityContext(testContext);
    }

    private void manipulateSecurityContext(String context) {
        // create debug security contexts for server
        SecurityContextManager scm = SecurityContextManager.getInstance();
        CommonContext cc = scm.getSecurityContextByHost(this.foreignHost.getHost());
        byte[] sequenceNumber = cc.getSenderContext().getSequenceNumber();

        CommonContext testContext;
        switch (context) {
            case "11":
                testContext = OscoapHelper
                        .getSecurityContextForClientFalseSenderID(this.foreignHost.getHost());
                testContext.getSenderContext().setSequenceNumber(sequenceNumber);
                scm.removeSecurityContext(cc);
                scm.addSecurityContext(testContext);
                break;
            case "12":
                testContext = OscoapHelper
                        .getSecurityContextForClientFalseSenderKey(this.foreignHost.getHost());
                testContext.getSenderContext().setSequenceNumber(sequenceNumber);
                scm.removeSecurityContext(cc);
                scm.addSecurityContext(testContext);
                break;
            case "13":
                testContext = OscoapHelper
                        .getSecurityContextForClientFalseRecipientKey(this.foreignHost.getHost());
                testContext.getSenderContext().setSequenceNumber(sequenceNumber);
                scm.removeSecurityContext(cc);
                scm.addSecurityContext(testContext);
                break;
            case "14":
                testContext = OscoapHelper
                        .getSecurityContextForClientDefault(this.foreignHost.getHost());

                // Wird zwar über den Test schon abgefragt, aber sicher ist sicher
                if (sequenceNumber.length > 0 && sequenceNumber[0] > 0) {
                    sequenceNumber[0] = (byte) (sequenceNumber[0] - 1);
                }

                testContext.getSenderContext().setSequenceNumber(sequenceNumber);
                scm.removeSecurityContext(cc);
                scm.addSecurityContext(testContext);
                break;
        }
    }

    private void runSpecificTest(int test) {
        System.out.println("Running test "+ test +" ===================================================");
        switch (test) {
            case 0:
                performTest00();
                break;
            case 1:
                performTest01();
                break;
            case 2:
                performTest02();
                break;
            case 3:
                performTest03();
                break;
            case 4:
                performTest04();
                break;
            case 5:
                performTest05();
                break;
            case 6:
                performTest06();
                break;
            case 7:
                performTest07();
                break;
            case 8:
                performTest08();
                break;
            case 9:
                performTest09();
                break;
            case 10:
                performTest10();
                break;
            case 11:
                performTest11();
                break;
            case 12:
                performTest12();
                break;
            case 13:
                performTest13();
                break;
            case 14:
                performTest14();
                break;
            case 15:
                performTest15();
                break;
            case 16:
                performTest16();
                break;
        }
    }
    private void runAllTests() {
        int sleepTimeMillis = 1000;

        try {
            performTest00();
            Thread.sleep(sleepTimeMillis);
            performTest01();
            Thread.sleep(sleepTimeMillis);
            performTest02();
            Thread.sleep(sleepTimeMillis);
            performTest03();
            Thread.sleep(sleepTimeMillis);
            performTest04();
            Thread.sleep(sleepTimeMillis);
            performTest05();
            Thread.sleep(sleepTimeMillis);
            performTest06();
            Thread.sleep(sleepTimeMillis);
            performTest07();
            Thread.sleep(sleepTimeMillis);
            performTest08();
            Thread.sleep(sleepTimeMillis);
            performTest09();
            Thread.sleep(sleepTimeMillis);
            performTest10();
            Thread.sleep(sleepTimeMillis);
            performTest11();
            Thread.sleep(sleepTimeMillis);
            performTest12();
            Thread.sleep(sleepTimeMillis);
            performTest13();
            Thread.sleep(sleepTimeMillis);
            performTest14();
            Thread.sleep(sleepTimeMillis);
            performTest15();
            Thread.sleep(sleepTimeMillis);
            performTest16();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    /**
     * verify that CoAP exchange works
     */
    private void performTest00() {

        String testUri = baseTestUri + "/hello/coap";
        client.setURI(testUri);
        Request request = Request.newGet();
        SecurityContextManager.getInstance().sendUnsecured(request);
        CoapResponse response = client.advanced(request);
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().equals("Hello World!")
                && response.getOptions().hasContentFormat()
                && response.getOptions().getContentFormat() == 0)
        {
            System.out.println("Test 0 result: Passed");
        } else {
            System.out.println("Test 0 result: Failed");
        }
    }

    private void performTest01() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().equals("Hello World!")
                && response.getOptions().hasContentFormat()
                && response.getOptions().getContentFormat() == 0)
        {
            System.out.println("Test 1 result: Passed");
        } else {
            System.out.println("Test 1 result: Failed");
        }
    }

    private void performTest02() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/2?first=1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().equals("Hello World!")
                && response.getOptions().hasContentFormat()
                && response.getOptions().getContentFormat() == 0
                && response.getOptions().containsETag(new byte[]{43}))
        {
            System.out.println("Test 2 result: Passed");
        } else {
            System.out.println("Test 2 result: Failed");
        }
    }

    private void performTest03() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/3";
        client.setURI(testUri);
        CoapResponse response = client.get(0); // set accept = 0
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().equals("Hello World!")
                && response.getOptions().hasContentFormat()
                && response.getOptions().getContentFormat() == 0
                && response.getOptions().hasMaxAge()
                && response.getOptions().getMaxAge() == 5)
        {
            System.out.println("Test 3 result: Passed");
        } else {
            System.out.println("Test 3 result: Failed");
        }
    }

    private void performTest04() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        Request request = Request.newGet();
        request.getOptions().setObserve(0);
        CoapResponse response = client.advanced(request);

        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && !response.getOptions().hasObserve()
                && response.getResponseText().equals("Hello World!"))
        {
            System.out.println("Test 4 result: Passed");
        } else {
            System.out.println("Test 4 result: Failed");
        }
    }

    private void performTest05() {
        setDefaultSecurityContext();

        String testUri = baseTestUri + "/observe";
        client.setURI(testUri);

        CoapHandler handler = new CoapHandler() {
            @Override
            public void onLoad(CoapResponse response) {
                debugPrintResponse(response);

                if (response != null
                        && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                        && response.getResponseText().substring(0,7).equals("Counter"))
                {
                    System.out.println("Test 5 result: Passed Observe Notification");
                } else {
                    System.out.println("Test 5 result: Failed Observe Notification");
                }
            }

            @Override
            public void onError() {
                System.out.println("onError in observe");
            }
        };

        CoapObserveRelation relation = client.observe(handler);

        System.out.println("start observe");
        try {
            Thread.sleep(5000);
            System.out.println("end observe");
            relation.proactiveCancel();
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    private void performTest06() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/6";
        client.setURI(testUri);
        CoapResponse response = client.post(new byte[]{74}, 0); // 0x4a
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CHANGED.value)
        {
            System.out.println("Test 6 result: Passed");
        } else {
            System.out.println("Test 6 result: Failed");
        }
    }

    private void performTest07() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/7";
        client.setURI(testUri);

        // payload=0x7a, ifMatch=0x7b
        CoapResponse response = client.putIfMatch(new byte[]{122}, 0, new byte[]{123});

        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CHANGED.value)
        {
            System.out.println("Test 7 result: Passed");
        } else {
            System.out.println("Test 7 result: Failed");
        }
    }

    private void performTest08() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/7";
        client.setURI(testUri);

        // payload=0x7a
        CoapResponse response = client.putIfNoneMatch(new byte[]{122}, 0);

        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.PRECONDITION_FAILED.value)
        {
            System.out.println("Test 8 result: Passed");
        } else {
            System.out.println("Test 8 result: Failed");
        }
    }

    private void performTest09() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/test";
        client.setURI(testUri);
        CoapResponse response = client.delete();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.DELETED.value)
        {
            System.out.println("Test 9 result: Passed");
        } else {
            System.out.println("Test 9 result: Failed");
        }
    }

    private void performTest10() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/large";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().contains("RESOURCE BLOCK NO. 1 OF 5")
                && response.getResponseText().contains("RESOURCE BLOCK NO. 2 OF 5")
                && response.getResponseText().contains("RESOURCE BLOCK NO. 3 OF 5")
                && response.getResponseText().contains("RESOURCE BLOCK NO. 4 OF 5")
                && response.getResponseText().contains("RESOURCE BLOCK NO. 5 OF 5"))
        {
            System.out.println("Test 10 result: Passed");
        } else {
            System.out.println("Test 10 result: Failed");
        }
    }

    private void performTest11() {
        manipulateSecurityContext("11");
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.UNAUTHORIZED.value)
        {
            String additionalOutput = "";
            if (response.getResponseText().toLowerCase().equals("security context not found")){
                additionalOutput = " Also got the optional payload \"Security context not found\"";
            }
            System.out.println("Test 11 result: Passed."+additionalOutput);

        } else {
            System.out.println("Test 11 result: Failed");
        }
    }

    private void performTest12() {
        manipulateSecurityContext("12");
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.BAD_REQUEST.value)
        {
            String additionalOutput = "";
            if (response != null
                    && response.getResponseText().toLowerCase().equals("decryption failed")){
                additionalOutput = " Also got the optional payload \"Decryption failed\"";
            }
            System.out.println("Test 12 result: Passed."+additionalOutput);
        } else {
            System.out.println("Test 12 result: Failed");
        }
    }

    private void performTest13() {
        manipulateSecurityContext("13");
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        System.out.println("Test 13 Passed, if the parsing ends in an OscoapException with \"Decryption failed\"");
    }

    private void performTest14() {
        SecurityContextManager scm = SecurityContextManager.getInstance();
        CommonContext cc = scm.getSecurityContextByHost(this.foreignHost);
        byte[] sequenceNumber = cc.getSenderContext().getSequenceNumber();
        if (sequenceNumber.length < 1 || (sequenceNumber.length == 1 && sequenceNumber[0] == 0)) {
            System.out.println("Do not run this test as the first one, there must be a sequence number > 0!");
            return;
        }
        setDefaultSecurityContext();

        // first request
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        boolean message1TestResult = false;
        if (response != null
                && response.getCode().value == CoAP.ResponseCode.CONTENT.value
                && response.getResponseText().equals("Hello World!")
                && response.getOptions().hasContentFormat()
                && response.getOptions().getContentFormat() == 0)
        {
            message1TestResult = true;
        }

        // decrement sequence number
        manipulateSecurityContext("14");

        client.setURI(testUri);
        CoapResponse response2 = client.get();
        debugPrintResponse(response2);

        boolean message2TestResult = false;
        if (response2 != null
                && response2.getCode().value == CoAP.ResponseCode.BAD_REQUEST.value)
        {
            message2TestResult = true;
        }

        if (message1TestResult && message2TestResult) {
            String additionalOutput = "";
            if (response2 != null
                    && response2.getResponseText().toLowerCase().equals("replay protection failed"))
            {
                additionalOutput = " Also got the optional payload \"Replay protection failed\"";
            }
            System.out.println("Test 14 result: Passed"+additionalOutput);
        } else {
            System.out.println("Test 14 result: Failed");
        }
    }

    private void performTest15() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/coap";
        client.setURI(testUri);
        CoapResponse response = client.get();
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.BAD_OPTION.value)
        {
            System.out.println("Test 15 result: Passed");
        } else {
            System.out.println("Test 15 result: Failed (Fails always with Californium)");
        }
    }

    private void performTest16() {
        setDefaultSecurityContext();
        String testUri = baseTestUri + "/hello/1";
        client.setURI(testUri);
        Request request = Request.newGet();
        SecurityContextManager.getInstance().sendUnsecured(request);
        CoapResponse response = client.advanced(request);
        debugPrintResponse(response);

        if (response != null
                && response.getCode().value == CoAP.ResponseCode.UNAUTHORIZED.value)
        {
            System.out.println("Test 16 result: Passed");
        } else {
            System.out.println("Test 16 result: Failed (Will currently always fail, because this is still mission feature");
        }
    }
}
