# OSCORE for Californium

This project was created as a part of a master thesis by Luka Dschaak. The Title was 'Developement and Implementation of Object Security in Californium using OSCOAP'. As you can see, the implementation is based on the old Version OSCOAP. The exact Version is https://tools.ietf.org/html/draft-ietf-core-object-security-03.

The Object Security Option number was selected to 52225. It is placed as constant in OscoapEndpoint. To change it, you have to rebuild the project.


## use oscoap-0.1.jar
Currently the library is not available via repository. To use it, it must be included manually, as well the the following dependencies:

group: 'com.augustcellars.cose', name: 'cose-java', version:'0.9.6'  
group: 'org.eclipse.californium', name: 'californium-core', version:'1.0.6'  
group: 'org.eclipse.californium', name: 'element-connector', version:'1.0.6'

Examplecode of how Server and Client can be used, is found in the source files OscoapTestClient and OscoapTestServer


## Build with gradle
There are some different gradle tasks defined. For the the usual library, which can be included in an existing project, use `gradle jar`. There are two test classes for a standalone use. With `gradle fatJarTestServer` a standalone version of the OscoapTestServer will be compiled. With `gradle fatJarTestClient` get the same for the client.

All Jars are placed under build/libs/.


## Run TestServer and TestClient
`java -jar build/libs/oscoap-test-server_standalone-0.1.jar` or `java -jar build/libs/oscoap-test-client_standalone-0.1.jar`. Start server first!

There must be a first parameter! It should be the address (e.g. ip address) for the other endpoint. This is important for the security context.

For example:
Server: 192.168.0.20
Client: 192.168.0.30

    $ java -jar build/libs/oscoap-test-server_standalone-0.1.jar 192.168.0.30
    $ java -jar build/libs/oscoap-test-client_standalone-0.1.jar 192.168.0.20

Both try to find out the own address and display that on the console. If it is the wrong address, just pass it as second parameter to the call.

    $ java -jar build/libs/oscoap-test-server_standalone-0.1.jar 192.168.0.30 192.168.0.20
    $ java -jar build/libs/oscoap-test-client_standalone-0.1.jar 192.168.0.20 192.168.0.30

The Server starts an OscoapEndpoint and provides several resources. The client has a small test routine. After starting the client a ping check will be done first. If it fails once, just try starting the client again.

After ping you can choose between 'n' for next test (starts with 0), 'all' fo running all 16 tests, 'exit' for closing the client or type a [number] for selecting a specific test.

Examples on localhost with different ports and IPv6 use (only server):
Please use '127.0.0.1' instead of 'localhost' and '0:0:0:0:0:0:0:1' instead of  '::1'

    $ java -jar build/libs/oscoap-test-server_standalone-0.1.jar 127.0.0.1:27332 127.0.0.1:27331
    $ java -jar build/libs/oscoap-test-server_standalone-0.1.jar [0:0:0:0:0:0:0:1]:27332 [0:0:0:0:0:0:0:1]:27331
