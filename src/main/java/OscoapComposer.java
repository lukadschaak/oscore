import COSE.CoseException;
import COSE.Encrypt0Message;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.network.serialization.DatagramWriter;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Logger;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Transforms unprotected Message into protected.
 * Created by Luka Dschaak on 26.07.2017.
 */
public class OscoapComposer {

    private final static Logger LOGGER = Logger.getLogger(OscoapComposer.class.getCanonicalName());

    private boolean isRequest = false;
    private boolean isResponse = false;

    private boolean isObserve = false; // only for Responses

    public Request composeRequest(Request request) throws OscoapException {
        this.isRequest = true;
        return (Request) this.compose(request);
    }

    public Response composeResponse(Response response) throws OscoapException {
        this.isResponse = true;
        return (Response) this.compose(response);
    }

    /**
     * Does several steps to compose a protected CoAP message.
     * Input is the unprotected message. Returns a cloned message
     * Is synchronized because of sequence number. It shall avoid
     * the parallel use of the same sequence number in messages.
     * @param message The unprotected message
     * @return The protected message
     * @throws OscoapException Which should be handled properly,
     * like in OscoapEndpoint.
     */
    private synchronized Message compose(Message message) throws OscoapException {

        SecurityContextManager scm = SecurityContextManager.getInstance();
        CommonContext securityContext = null;
        if (isResponse) {
            // the method works via the OscoapRequestParameter.
            // So if there is no Security Context who contains a OscoapRequestParameter
            // with this token, there was no secured request. Maybe there was a request,
            // but then the response must not be protected.
            securityContext = scm.getSecurityContextByToken(message.getToken());
            if (securityContext == null) {
                // return message unmodified
                return message;
            }
        }

        if (isRequest) {
            if (scm.shallBeUnsecured( (Request) message)) {
                // return message unmodified
                return message;
            }
        }

        if (isResponse) {
            this.isObserve = message.getOptions().hasObserve();
            LOGGER.info("compose response");
        } else {
            LOGGER.info("compose request");
        }

        
        // We do not want to change options and payload on the
        // original of the request or the response.
        // For Blockwise and Observe it is necessary to keep the
        // original versions of the messages in the Exchanges.
        // Californium uses them to reset a observe relation, or
        // to send the Blockwise messages.
        if (isRequest) {
            message = cloneRequest( (Request) message );
        } else {
            message = cloneResponse( (Response) message );
        }


        // Step 1: Get Security Context by host
        String hostName = message.getDestination().getHostAddress();

        // Get by Host. If message is a response, maaaybe Security Context was
        // already found by Token.
        if (securityContext == null) {
            securityContext = scm.getSecurityContextByHost(hostName);
        }

        // synonym for senderID is kid, when used in COSE context
        byte[] senderID = securityContext.getSenderContext().getSenderID();
        byte[] senderIV = securityContext.getSenderContext().getSenderIV();
        byte[] senderKey = securityContext.getSenderContext().getSenderKey();


        // Step 2: Sequence number
        OscoapRequestParameter params;
        // requestID overwrites senderID if isResponse, but only in AAD
        byte[] requestID = null;
        // synonym for sequenceNumber is Partial IV, when used in COSE context
        byte[] sequenceNumber;
        if (isResponse && !isObserve) {
            // For Response, the parameters are not in the message.
            // They are stored while sending the request
            params = securityContext.getAndRemoveRequestParameters(message.getToken());
            requestID = params.getRequestID();
            sequenceNumber = params.getSequenceNumber();
        } else {
            // requestID can be null, because it is only used for isReponse && !isObserve.
            // For the opposite case senderID will be used.
            sequenceNumber = securityContext.getSenderContext().getSequenceNumber();
        }


        // Step 3: Additional Authenticated Data
        // First split the options into CLASS U, I and E
        // unpreotected, integrity protected and encrypted

        // For Class I use an empty set, because only observe may be placed here
        OptionSet integrityProtectedSet = new OptionSet();

        OptionSet protectedSet = new OptionSet(message.getOptions());

        this.distributeOptions(message, integrityProtectedSet, protectedSet, sequenceNumber);

        // With the integrityProtectedSet, create the aad
        byte[] externalAADEndpointID;
        if (isRequest || isObserve) {
            externalAADEndpointID = senderID;
        } else {
            externalAADEndpointID = requestID;
        }
        CBORObject external_aad = OscoapSerializer.getExternalAAD(
                message, securityContext, externalAADEndpointID, sequenceNumber, integrityProtectedSet
        );


        // Step 4: Plaintext
        // Put protectedSet together with original payload
        byte[] plaintext = this.getPlaintext(message, protectedSet);


        // Step 5: Encryption
        // use COSE_Encrypt0
        Encrypt0Message encryptMessage = null;
        try {
            // sequenceNumber is synonym for Partial IV in this context
            // senderID is synonym for kid in this context
            encryptMessage = OscoapSerializer.getCoseEncrypt0(
                    securityContext, sequenceNumber, senderID, senderIV, isRequest, isObserve);
        } catch (CoseException e) {
            throw new OscoapException("Internal Cose Error", OscoapException.SEND_NOTHING, null, null);
        }

        try {
            encryptMessage.SetContent(plaintext);

            encryptMessage.setExternal(external_aad.EncodeToBytes());

            encryptMessage.encrypt(senderKey);
        } catch (CoseException | InvalidCipherTextException e) {
            throw new OscoapException("Encryption Failed", OscoapException.SEND_NOTHING, null, null);
        }


        // Step 6: Compressing Payload
        byte[] compressedPayload = new byte[0];
        // sequenceNumber is synonym for Partial IV in this context
        // senderID is synonym for kid in this context
        try {
            if (isRequest) {
                compressedPayload = this.getCompressedPayload(sequenceNumber, senderID, encryptMessage.getEncryptedContent());
            } else {
                if (isObserve) {
                    compressedPayload = this.getCompressedPayload(sequenceNumber, null, encryptMessage.getEncryptedContent());
                } else {
                    compressedPayload = this.getCompressedPayload(null, null, encryptMessage.getEncryptedContent());
                }
            }
        } catch (CoseException e) {
            throw new OscoapException("Internal Cose Error", OscoapException.SEND_NOTHING, null, null);
        }


        // Step 7: Object Security Option
        if (message.getPayloadSize() > 0) {
            message.setPayload(compressedPayload);
            Option objectSecurityOption = new Option(OscoapEndpoint.OSCOAP_OPTION_NUMBER, new byte[0]);
            message.getOptions().addOption(objectSecurityOption);
        } else {
            Option objectSecurityOption = new Option(OscoapEndpoint.OSCOAP_OPTION_NUMBER, compressedPayload);
            message.getOptions().addOption(objectSecurityOption);
        }


        // Step 8: Update Security Context
        // Store current sequence number, BEFORE incrementing it
        if (isRequest) {
            byte[] token = message.getToken();
            OscoapRequestParameter newParams = new OscoapRequestParameter(sequenceNumber, senderID);
            securityContext.addRequestParameters(token, newParams);
        }

        if (isRequest || isObserve) {
            securityContext.getSenderContext().incrementSequenceNumber();
        }


        // do all the debug Logs on one place
        OscoapSerializer.logDebug("Composer", senderID, senderIV, senderKey, sequenceNumber, external_aad, compressedPayload, message.getToken());

        return message;
    }

    /**
     * Filters options in the unprotected and protected sets.
     * Copies values to integrityProtectedSet if needed (only observe).
     * @param message the Message with the unprotected OptionSet
     * @param integrityProtectedSet should be an empty optionSet
     * @param protectedSet a copy of the OptionSet from the message
     * @throws URISyntaxException When newUri(unprotectedSet.getProxyUri()) fails
     */
    private void distributeOptions(Message message, OptionSet integrityProtectedSet, OptionSet protectedSet, byte[] sequenceNumber) {

        // 1 clean up protected set
        // protected set is a clone of the original message option set.
        // so just remove the unprotected options
        protectedSet.removeUriHost();
        protectedSet.removeUriPort();
        protectedSet.removeProxyUri();
        protectedSet.removeProxyScheme();
        protectedSet.removeObserve();


        // 2 split ProxyUri option to Class U and Class E options
        OptionSet unprotectedSet = message.getOptions();

        try {
            if (unprotectedSet.hasProxyUri()) {
                // split proxyUri into
                // - Proxy-Scheme  Class U
                // - Uri-Host      Class U
                // - Uri-Port      Class U
                // - Uri-Path      Class E
                // - Uri-Query     Class E
                URI uri = new URI(unprotectedSet.getProxyUri());

                String scheme = uri.getScheme() == null ? "" : uri.getScheme()+":";
                String hostSpecificPart = uri.getSchemeSpecificPart().split(uri.getHost())[0];
                String port = uri.getPort() == -1 ? "" : ":"+uri.getPort();

                String unprotectedProxyUri = scheme + hostSpecificPart + uri.getHost() + port;

                unprotectedSet.setProxyUri(unprotectedProxyUri);

                if (!uri.getPath().equals("")) {
                    protectedSet.setUriPath(uri.getPath());
                }
                if (uri.getQuery() != null) {
                    protectedSet.setUriQuery(uri.getQuery());
                }
            }
        } catch (URISyntaxException e) {
            LOGGER.warning("Message contains malformed ProxyUri. It will be removed from Options, but Message will be send");
            unprotectedSet.removeProxyUri();
            e.printStackTrace();
        }


        // 3 clean up unprotected set
        OptionSet tmpOptionSet = new OptionSet();
        if (unprotectedSet.hasUriHost()) {
            tmpOptionSet.setUriHost(unprotectedSet.getUriHost());
        }
        if (unprotectedSet.hasUriPort()) {
            tmpOptionSet.setUriPort(unprotectedSet.getUriPort());
        }
        // If there was a ProxyUri in the original massage, this Option is already
        // modified above and only contains scheme, host and port.
        if (unprotectedSet.hasProxyUri()) {
            tmpOptionSet.setProxyUri(unprotectedSet.getProxyUri());
        }
        if (unprotectedSet.hasProxyScheme()) {
            tmpOptionSet.setProxyScheme(unprotectedSet.getProxyScheme());
        }
        // For Request and also Response, the Observe shall be an outer value
        if (unprotectedSet.hasObserve()) {
            tmpOptionSet.setObserve(unprotectedSet.getObserve());
        }

        // override the unprotexted option set with the temp option set
        message.setOptions(tmpOptionSet);


        // 4 fill integrity protected set
        // integrity protected set is empty.
        // Observe has different behaviours
        // In Request its value is 0 or 1 and is a encrypted option.
        // In Responses the value is set to the 3 least significant bytes of the SEQUENCE NUMBER
        if (isResponse && message.getOptions().hasObserve()) {
            int cuttedSequenceNumber = OscoapSerializer.getLeastSignificantBytes(sequenceNumber);
            integrityProtectedSet.setObserve(cuttedSequenceNumber);
        }


        if (isResponse) {
            unprotectedSet.setMaxAge(0);
        }

        // Blockoptions
        // This here will be called, after splitting into blocks was done. Do this.message would be a splitted
        // CoAP message. Because of this, there is nothing to do here.
    }

    private byte[] getPlaintext(Message message, OptionSet protectedSet) {

        DatagramWriter writer = new DatagramWriter();

        byte[] encodedOptionSet = OscoapSerializer.encodeOptionSet(protectedSet);
        writer.writeBytes(encodedOptionSet);

        if (message.getPayloadSize() > 0) {
            // if payload is present and of non-zero length, it is prefixed by
            // an one-byte Payload Marker (0xFF) which indicates the end of
            // options and the start of the payload
            writer.writeByte(PAYLOAD_MARKER);
            writer.writeBytes(message.getPayload());
        }

        return writer.toByteArray();
    }

    /**
     * I tried working without any kind of streams.
     * So this is raw byte copying.
     * @param partialIV the partialIV is added in the returned byte array
     * @param kid the kid is added in the returned byte array
     * @param payload the payload is added in the returned byte array
     * @return compressedPayload as byte array
     */
    private byte[] getCompressedPayload(byte[] partialIV, byte[] kid, byte[] payload) {
        byte flags = (byte) 0;
        int compressedPayloadLength = 1;

        if (partialIV != null) {
            flags = (byte) partialIV.length;
            compressedPayloadLength += partialIV.length;
        } // else leave the bit 0, that means partialIV is not present

        if (kid != null) {
            flags = (byte) (flags | 8);
            compressedPayloadLength += 1;
            compressedPayloadLength += kid.length;
        }

        if (payload != null) {
            compressedPayloadLength += payload.length;
        }

        // 1 for flags
        // partialIV
        // 1 Byte for length of kid
        // n bytes for payload
        byte[] compressedPayload = new byte[compressedPayloadLength];
        int insertingIndex = 0;

        compressedPayload[insertingIndex] = flags;
        insertingIndex++;

        if (partialIV != null) {
            System.arraycopy(partialIV, 0, compressedPayload, insertingIndex, partialIV.length);
            insertingIndex += partialIV.length;
        }

        if (kid != null) {
            compressedPayload[insertingIndex] = (byte) kid.length;
            insertingIndex++;

            System.arraycopy(kid, 0, compressedPayload, insertingIndex, kid.length);
            insertingIndex += kid.length;
        }

        if( payload != null ) {
            System.arraycopy(payload, 0, compressedPayload, insertingIndex, payload.length);
        }

        return compressedPayload;
    }
    
    private Request cloneRequest(Request request) {
        Request clonedRequest = new Request(request.getCode());

        // Copy values inherited from Message
        clonedRequest.setAcknowledged(request.isAcknowledged());
        clonedRequest.setCanceled(request.isCanceled());
        clonedRequest.setConfirmable(request.isConfirmable());
        clonedRequest.setDestination(request.getDestination());
        clonedRequest.setDestinationPort(request.getDestinationPort());
        clonedRequest.setDuplicate(request.isDuplicate());
        clonedRequest.setMID(request.getMID());
        clonedRequest.setOptions(new OptionSet(request.getOptions()));
        clonedRequest.setPayload(request.getPayload());
        clonedRequest.setRejected(request.isRejected());
        clonedRequest.setSource(request.getSource());
        clonedRequest.setTimedOut(request.isTimedOut());
        clonedRequest.setTimestamp(request.getTimestamp());
        clonedRequest.setToken(request.getToken());
        clonedRequest.setType(request.getType());

        // Request specific values
        clonedRequest.setMulticast(request.isMulticast());
        clonedRequest.setScheme(request.getScheme());
        clonedRequest.setURI(request.getURI());

        // Maybe it is better to not do the following, because after OscoapComposer
        // the message only will be converted to Bytes. There is no need
        // for setting references. The possibly to cause evil things is
        // higher than any advantage on my opinion.
        //clonedRequest.setResponse(request.getResponse());

        return clonedRequest;
    }

    private Response cloneResponse(Response response) {
        Response clonedResponse = new Response(response.getCode());

        // Copy values inherited from Message
        clonedResponse.setAcknowledged(response.isAcknowledged());
        clonedResponse.setCanceled(response.isCanceled());
        clonedResponse.setConfirmable(response.isConfirmable());
        clonedResponse.setDestination(response.getDestination());
        clonedResponse.setDestinationPort(response.getDestinationPort());
        clonedResponse.setDuplicate(response.isDuplicate());
        clonedResponse.setMID(response.getMID());
        clonedResponse.setOptions(new OptionSet(response.getOptions()));
        clonedResponse.setPayload(response.getPayload());
        clonedResponse.setRejected(response.isRejected());
        clonedResponse.setSource(response.getSource());
        clonedResponse.setTimedOut(response.isTimedOut());
        clonedResponse.setTimestamp(response.getTimestamp());
        clonedResponse.setToken(response.getToken());
        clonedResponse.setType(response.getType());

        // Response specific values
        clonedResponse.setRTT(response.getRTT());
        clonedResponse.setLast(response.isLast());

        return clonedResponse;
    }
}
