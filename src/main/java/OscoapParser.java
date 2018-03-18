import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.serialization.DatagramReader;

import java.util.List;
import java.util.logging.Logger;

import static org.eclipse.californium.core.coap.CoAP.MessageFormat.PAYLOAD_MARKER;

/**
 * Parse Oscoap Messages (Request/Response/EmptyMessage)
 * Created by Luka Dschaak on 16.07.2017.
 */
public class OscoapParser {

    private final static Logger LOGGER = Logger.getLogger(OscoapParser.class.getCanonicalName());

    private boolean isRequest = false;
    private boolean isResponse = false;

    private boolean isObserve = false; // only for Responses

    private byte[] sequenceNumber = null;
    private byte[] senderID = null;

    public Request parseRequest(Request request) throws OscoapException {
        this.isRequest = true;
        return (Request) this.parseMessage(request);
    }

    public Response parseResponse(Response response) throws OscoapException {
        this.isResponse = true;
        return (Response) this.parseMessage(response);
    }

    private Message parseMessage(Message message) throws OscoapException {
        if (!message.getOptions().hasOption(OscoapEndpoint.OSCOAP_OPTION_NUMBER)) {
            // Nothing special to do, its a unprotected message.
            return message;
        }

        if (isResponse) {
            // This works, because the Observe option is only integrity protected
            // and shall have an unprotected options value.
            this.isObserve = message.getOptions().hasObserve();
            LOGGER.info("Parser; parse response");
        } else {
            LOGGER.info("Parser; parse request");
        }


        // Step 1: Object Security Option
        // For the next developer: In californium 1.0.5 getOthers is public.
        // That would make the code a lot easier to read.
        byte[] securityOptionValue = new byte[0];
        boolean atLeastOneSecurityOption = false;
        List<Option> allOptions = message.getOptions().asSortedList();
        for (Option option : allOptions) {
            if (option.getNumber() == OscoapEndpoint.OSCOAP_OPTION_NUMBER) {
                if (atLeastOneSecurityOption) {
                    if (message.isConfirmable()) {
                        throw new OscoapException("Security option is not repeatable", OscoapException.SEND_RESPONSE, CoAP.Type.ACK, CoAP.ResponseCode.BAD_REQUEST);
                    } else {
                        throw new OscoapException("Security option is not repeatable", OscoapException.SEND_NOTHING, null, null);
                    }
                } else {
                    securityOptionValue = option.getValue();
                    atLeastOneSecurityOption = true;
                }
            }
        }


        // Step 2: Decompressing Payload
        // 2a: read the compressed payload
        byte[] compressedPayload;
        if (message.getPayloadSize() > 0) {

            // security option has to be empty if payload is set
            if (securityOptionValue.length > 0) {
                throw new OscoapException("malformed oscoap option", OscoapException.SEND_EMPTY, CoAP.Type.RST, null);
            }

            // compressed payload with ciphertext is in payload
            compressedPayload = message.getPayload();
        } else {

            // at least one of payload and option value must be not empty
            if (securityOptionValue.length < 1) {
                throw new OscoapException("malformed oscoap option", OscoapException.SEND_EMPTY, CoAP.Type.RST, null);
            }

            // compressed payload with ciphertext is in option value
            compressedPayload = securityOptionValue;
        }

        // 2b: decompress
        byte[] ciphertext = this.decompressPayload(compressedPayload);
        if (isRequest && senderID == null) {
            if (message.isConfirmable()) {
                throw new OscoapException("Failed to decode COSE", OscoapException.SEND_RESPONSE, CoAP.Type.ACK, CoAP.ResponseCode.BAD_REQUEST);
            } else {
                throw new OscoapException("Failed to decode COSE", OscoapException.SEND_NOTHING, null, null);
            }
        }


        // Step 3: Get Security Context
        // Get it either by senderID (Request), or by Token (Reponse)
        SecurityContextManager scm = SecurityContextManager.getInstance();
        CommonContext securityContext = null;
        if (isRequest) {
            securityContext = scm.getSecurityContextByID(senderID);
            if (securityContext == null) {
                if (message.isConfirmable()) {
                    throw new OscoapException("Security context not found", OscoapException.SEND_RESPONSE, CoAP.Type.ACK, CoAP.ResponseCode.UNAUTHORIZED);
                } else {
                    throw new OscoapException("Security context not found", OscoapException.SEND_NOTHING, null, null);
                }
            }
        } else if (isResponse) {
            securityContext = scm.getSecurityContextByToken(message.getToken());
            if (securityContext == null) {
                if (message.isConfirmable()) {
                    throw new OscoapException("Security context not found", OscoapException.SEND_EMPTY, CoAP.Type.ACK, null);
                } else {
                    throw new OscoapException("Security context not found", OscoapException.SEND_NOTHING, null, null);
                }
            }
        }
        byte[] recipientID = securityContext.getRecipientContext().getRecipientID();
        byte[] recipientIV = securityContext.getRecipientContext().getRecipientIV();
        byte[] recipientKey = securityContext.getRecipientContext().getRecipientKey();



        // Step 4: Sequence Number
        OscoapRequestParameter params = null;
        // requestID overwrites senderID if isResponse, but only in AAD
        byte[] requestID = null;
        if (isResponse && !isObserve) {
            params = securityContext.getAndRemoveRequestParameters(message.getToken());
            requestID = params.getRequestID();
        }

        // byte[] sequenceNumber is already defined, but still null in case of Response

        // Different to composer: check replay window
        if (isRequest || isObserve) {
            if (sequenceNumber == null) {
                throw new OscoapException(
                        "Replay Protection failed; sequence number should not be null",
                        OscoapException.SEND_NOTHING, null, null);
            }

            boolean sequenceNumberIsValid = securityContext.getRecipientContext().compareReplayWindow(sequenceNumber);
            if (!sequenceNumberIsValid) {
                if (message.isConfirmable()) {
                    if (isRequest) {
                        throw new OscoapException("Replay protection failed",
                                OscoapException.SEND_RESPONSE, CoAP.Type.ACK, CoAP.ResponseCode.BAD_REQUEST);
                    } else {
                        throw new OscoapException("Replay protection failed", OscoapException.SEND_EMPTY, CoAP.Type.ACK, null);
                    }
                } else {
                    throw new OscoapException("Replay protection failed", OscoapException.SEND_NOTHING, null, null);
                }
            }
            // else sequence number is good and can be used
        }
        if (isResponse && !isObserve) {
            sequenceNumber = params.getSequenceNumber();
        }


        // Step 5: Additional Authenticated Data

        // First get the integrity protected options (Observe)
        OptionSet integrityProtectedSet = this.getIntegrityProtectedOptions();

        // With the integrityProtectedSet, create the aad
        byte[] externalAADEndpointID;
        if (isRequest || isObserve) {
            externalAADEndpointID = recipientID;
        } else {
            externalAADEndpointID = requestID;
        }
        CBORObject external_aad = OscoapSerializer.getExternalAAD(
                message, securityContext, externalAADEndpointID, sequenceNumber, integrityProtectedSet
        );


        // Step 6: Decryption
        // use COSE_Encrypt0
        Encrypt0Message encryptMessage;
        try {
            // sequenceNumber is synonym for Partial IV in this context
            // recipientID is synonym for kid in this context
            encryptMessage = OscoapSerializer.getCoseEncrypt0(
                    securityContext, sequenceNumber, recipientID, recipientIV, isRequest, isObserve);
        } catch (CoseException e) {
            if (message.isConfirmable()) {
                throw new OscoapException("Internal Cose Error", OscoapException.SEND_RESPONSE,
                        CoAP.Type.ACK, CoAP.ResponseCode.INTERNAL_SERVER_ERROR);
            } else {
                throw new OscoapException("Internal Cose Error", OscoapException.SEND_NOTHING, null, null);
            }
        }

        // Plaintext is encrypted options with original payload
        byte[] plaintext;
        try {
            encryptMessage.setExternal(external_aad.EncodeToBytes());

            encryptMessage.setEncryptedContent(ciphertext);

            plaintext = encryptMessage.decrypt(recipientKey);
        } catch (CoseException | InvalidCipherTextException e) {
            OscoapSerializer.logDebug("Parser", recipientID, recipientIV, recipientKey, sequenceNumber, external_aad, compressedPayload, message.getToken());
            if (!message.isConfirmable()) {
                throw new OscoapException("Decryption failed", OscoapException.SEND_NOTHING, null, null);
            } else {
                int sendBehaviour;
                if (isRequest) {
                    sendBehaviour = OscoapException.SEND_RESPONSE;
                } else {
                    sendBehaviour = OscoapException.SEND_EMPTY;
                }
                throw new OscoapException("Decryption failed", sendBehaviour, CoAP.Type.ACK, CoAP.ResponseCode.BAD_REQUEST);
            }
        }


        // Step 7: Decompose Plaintext
        // 7.2.4. says, update replay window here, before decompose plaintext
        if (isRequest || isObserve) {
            securityContext.getRecipientContext().updateReplayWindow(sequenceNumber);
        }

        // The method splits plaintext into encrypted options and original payload
        // the options are merged with the unprotected options and the payload
        // is assigned to the message
        this.decomposePlaintext(plaintext, message);


        // Step 8: Update Security Context
        if (isRequest) {
            byte[] token = message.getToken();
            OscoapRequestParameter newParams = new OscoapRequestParameter(sequenceNumber, recipientID);
            securityContext.addRequestParameters(token, newParams);
        }


        // do all the debug Logs on one place
        OscoapSerializer.logDebug("Parser", recipientID, recipientIV, recipientKey, sequenceNumber, external_aad, compressedPayload, message.getToken());

        return message;
    }

    private byte[] decompressPayload(byte[] compressedPayload) {
        int readIndex = 0;
        byte flags = compressedPayload[readIndex];
        readIndex++;

        // least significant 3 bits
        int seqNumLength = flags & 7;

        if (seqNumLength > 0) {
            sequenceNumber = new byte[seqNumLength];
            System.arraycopy(compressedPayload, readIndex, sequenceNumber, 0, seqNumLength);
        }
        readIndex += seqNumLength;

        boolean senderIDPresent = (flags & 8) > 0;

        if (senderIDPresent) {
            int senderIDLength = compressedPayload[readIndex];
            readIndex++;

            senderID = new byte[senderIDLength];
            System.arraycopy(compressedPayload, readIndex, senderID, 0, senderIDLength);
            readIndex += senderIDLength;
        }

        byte[] payload = new byte[compressedPayload.length - readIndex];
        System.arraycopy(compressedPayload, readIndex, payload, 0, payload.length);

        return payload;
    }

    /**
     * In OscoapSerializer.distributeOptions, the unprotected options are seperated
     * and distributed in the different option sets. Only the integrity protected are
     * needed for parsing (for external_aad for decryption)
     * @return The integrity protected OptionSet
     */
    private OptionSet getIntegrityProtectedOptions() {
        OptionSet integrityProtectedSet = new OptionSet();

        if (isResponse && isObserve) {
            int cuttedSequenceNumber = OscoapSerializer.getLeastSignificantBytes(sequenceNumber);
            integrityProtectedSet.setObserve(cuttedSequenceNumber);
        }

        return integrityProtectedSet;
    }

    private void decomposePlaintext(byte[] plaintext, Message message) {
        byte[] options;
        byte[] originalPayload = null;

        int payloadMarker = -1;
        for (int i = 0; i < plaintext.length; i++) {
            byte payloadByte = plaintext[i];
            if (payloadByte == PAYLOAD_MARKER) {
                payloadMarker = i;
                break;
            }
        }

        if (payloadMarker == -1) {
            options = plaintext;
        } else {
            options = new byte[payloadMarker];
            System.arraycopy(plaintext, 0, options, 0, payloadMarker);

            int payloadLength = plaintext.length - payloadMarker - 1;
            originalPayload = new byte[payloadLength];
            System.arraycopy(plaintext, payloadMarker+1, originalPayload, 0, payloadLength);
        }

        // protectedSet is going to be the merged set
        OptionSet protectedSet = this.parseOptionSet(options);
        OptionSet unprotectedSet = new OptionSet(message.getOptions());

        // merge protectedSet into message (unprotectedSet)
        // There are only 5 Class U options. So copy them to the protectedSet, if
        // they appear. Afterwards assign the protectedSet to the message.
        // only ProxyUri is a bit complex
        if (unprotectedSet.hasProxyUri()) {
            String originalProxyUri = unprotectedSet.getProxyUri();
            if (protectedSet.getUriPath().size() > 0) {
                originalProxyUri += "/" + protectedSet.getUriPathString();
                protectedSet.clearUriPath();
            }
            if (protectedSet.getUriQuery().size() > 0) {
                originalProxyUri += "?" + protectedSet.getUriQueryString();
                protectedSet.clearUriQuery();
            }
            protectedSet.setProxyUri(originalProxyUri);
        }

        if (unprotectedSet.hasUriHost()) {
            protectedSet.setUriHost(unprotectedSet.getUriHost());
        }
        if (unprotectedSet.hasUriPort()) {
            protectedSet.setUriPort(unprotectedSet.getUriPort());
        }
        if (unprotectedSet.hasProxyScheme()) {
            protectedSet.setProxyScheme(unprotectedSet.getProxyScheme());
        }
        if (unprotectedSet.hasObserve()) {
            protectedSet.setObserve(unprotectedSet.getObserve());
        }
        message.setOptions(protectedSet);


        if (originalPayload != null) {
            message.setPayload(originalPayload);
        }
    }

    /**
     * Adapted from org.eclipse.californium.core.network.serialization.DataParser
     * @param options the options as byte
     * @return parsed option set as OptionSet
     */
    private OptionSet parseOptionSet(byte[] options) {
        DatagramReader reader = new DatagramReader(options);
        OptionSet result = new OptionSet();

        int currentOption = 0;
        byte nextByte;
        while(reader.bytesAvailable()) {
            nextByte = reader.readNextByte();
            // the first 4 bits of the byte represent the option delta
            int optionDeltaNibble = (0xF0 & nextByte) >> 4;
            currentOption += readOptionValueFromNibble(reader, optionDeltaNibble);

            // the second 4 bits represent the option length
            int optionLengthNibble = (0x0F & nextByte);
            int optionLength = readOptionValueFromNibble(reader, optionLengthNibble);

            // read option
            Option option = new Option(currentOption);
            option.setValue(reader.readBytes(optionLength));

            // add option to message
            result.addOption(option);
        }

        return result;
    }

    private int readOptionValueFromNibble(DatagramReader reader, int nibble) {
        if (nibble <= 12) {
            return nibble;
        } else if (nibble == 13) {
            return reader.read(8) + 13;
        } else if (nibble == 14) {
            return reader.read(16) + 269;
        } else {
            throw new IllegalArgumentException("Unsupported option delta "+nibble);
        }
    }
}
