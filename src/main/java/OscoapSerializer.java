import COSE.*;
import com.upokecenter.cbor.CBORObject;
import org.eclipse.californium.core.coap.*;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.serialization.DatagramWriter;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.logging.Logger;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_DELTA_BITS;
import static org.eclipse.californium.core.coap.CoAP.MessageFormat.OPTION_LENGTH_BITS;

/**
 * Transforms unprotected Message into protected.
 * Created by Luka Dschaak on 14.07.2017.
 */
public class OscoapSerializer {

    private final static Logger LOGGER = Logger.getLogger(OscoapSerializer.class.getCanonicalName());

    static void logDebug(String source, byte[] ID, byte[] IV, byte[] key, byte[] sequenceNumber, CBORObject external_aad, byte[] compressedPayload, byte[] token) {
        System.out.println(
                source+"; ID: "+ printHexBinary(ID) +", "+
                "IV: "+ printHexBinary(IV) +", "+
                "Key: "+ printHexBinary(key) +", "+
                "seq.Number: "+ printHexBinary(sequenceNumber));
        System.out.println(source+"; External AAD: "+ printHexBinary(external_aad.EncodeToBytes()));
        System.out.println(source+"; compressed payload: " + printHexBinary(compressedPayload));
        System.out.println(source+"; token: " + printHexBinary(token));
    }

    // copied from org.eclipse.californium.core.network.serialization.DataSerializer
    static byte[] encodeOptionSet(OptionSet set) {
        DatagramWriter writer = new DatagramWriter();

        List<Option> options = set.asSortedList(); // already sorted
        int lastOptionNumber = 0;
        for (Option option:options) {

            // write 4-bit option delta
            int optionDelta = option.getNumber() - lastOptionNumber;
            int optionDeltaNibble = getOptionNibble(optionDelta);
            writer.write(optionDeltaNibble, OPTION_DELTA_BITS);

            // write 4-bit option length
            int optionLength = option.getLength();
            int optionLengthNibble = getOptionNibble(optionLength);
            writer.write(optionLengthNibble, OPTION_LENGTH_BITS);

            // write extended option delta field (0 - 2 bytes)
            if (optionDeltaNibble == 13) {
                writer.write(optionDelta - 13, 8);
            } else if (optionDeltaNibble == 14) {
                writer.write(optionDelta - 269, 16);
            }

            // write extended option length field (0 - 2 bytes)
            if (optionLengthNibble == 13) {
                writer.write(optionLength - 13, 8);
            } else if (optionLengthNibble == 14) {
                writer.write(optionLength - 269, 16);
            }

            // write option value
            writer.writeBytes(option.getValue());

            // update last option number
            lastOptionNumber = option.getNumber();
        }

        return writer.toByteArray();
    }

    /**
     * Returns the 4-bit option header value.
     *
     * @param optionValue
     *            the option value (delta or length) to be encoded.
     * @return the 4-bit option header value.
     */
    private static int getOptionNibble(int optionValue) {
        if (optionValue <= 12) {
            return optionValue;
        } else if (optionValue <= 255 + 13) {
            return 13;
        } else if (optionValue <= 65535 + 269) {
            return 14;
        } else {
            throw new IllegalArgumentException("Unsupported option delta "+optionValue);
        }
    }

    protected static CBORObject getExternalAAD(Message message, CommonContext securityContext,
                                      byte[] kid, byte[] sequenceNumber, OptionSet integrityProtectedSet) {
        CBORObject external_aad = CBORObject.NewArray();

        // ver: unit // index: 0
        external_aad.Add(CBORObject.FromObject(CoAP.VERSION));

        // code: unit // index: 1
        external_aad.Add(CBORObject.FromObject(getCodeValue(message)));

        // options: bstr // index: 2
        byte[] encodedOptions = encodeOptionSet(integrityProtectedSet);
        external_aad.Add(CBORObject.FromObject(encodedOptions));

        // alg: int // index: 3
        external_aad.Add(securityContext.getAlgorithm().AsCBOR());

        // request_kid: bstr // index: 4
        external_aad.Add(CBORObject.FromObject(kid));

        // request_seq: bstr // index: 5
        external_aad.Add(CBORObject.FromObject(sequenceNumber));

        boolean debug = false;
        if (debug) {
            System.out.println("External Additional Authenticated Data:");
            System.out.println("External AAD; Code Value: " + getCodeValue(message));
            System.out.println("External AAD; integrityProtectedSet: " + printHexBinary(encodedOptions));
            System.out.println("External AAD; integrityProtectedSet: " + integrityProtectedSet.toString());
            System.out.println("External AAD; Algorithm: " + securityContext.getAlgorithm().name());
            System.out.println("External AAD; kid: " + printHexBinary(kid));
        }

        return external_aad;
    }

    private static int getCodeValue(Message message) {
        if (message instanceof Request) {
            return ((Request) message).getCode().value;
        } else if (message instanceof Response) {
            return ((Response) message).getCode().value;
        } else {
            // this will absolutely never happen!
            return 0;
        }
    }

    static byte[] flipContextIVForResponses(byte[] contextIV) {
        if (contextIV.length > 0) {
            contextIV[0] = (byte) (contextIV[0] ^ (1 << 7));
        }
        return contextIV;
    }

    static Encrypt0Message getCoseEncrypt0(
            CommonContext securityContext, byte[] sequenceNumber, byte[] endpointID, byte[] endpointIV, boolean isRequest, boolean isObserve) throws CoseException {

        // For Responses, flip the most significant bit of the least significant byte
        // of the contextIV for security proposes
        byte[] contextIV = new byte[endpointIV.length];
        System.arraycopy(endpointIV, 0, contextIV, 0, endpointIV.length);
        if (!isRequest && !isObserve) { // => "normal" response
            contextIV = OscoapSerializer.flipContextIVForResponses(contextIV);
        }

        Encrypt0Message encryptMessage = new Encrypt0Message();

        if (isRequest || isObserve) {
            encryptMessage.addAttribute(HeaderKeys.PARTIAL_IV, CBORObject.FromObject(sequenceNumber), Attribute.UNPROTECTED);
        }
        if (isRequest) {
            encryptMessage.addAttribute(HeaderKeys.KID, CBORObject.FromObject(endpointID), Attribute.UNPROTECTED);
        }

        AlgorithmID alg = securityContext.getAlgorithm();
        encryptMessage.addAttribute(HeaderKeys.Algorithm, alg.AsCBOR(), Attribute.DO_NOT_SEND);

        // Make the IV by XORing sequence number and contextIV
        // Pad the sequenceNumber (partialIV) with zeros to the length of the contextIV
        // to make XORing possible
        byte[] sequenceNumberBytes = ByteBuffer.allocate(contextIV.length).put(sequenceNumber).array();
        byte[] iv = new byte[contextIV.length];

        // Do the XORing
        for (int byteIndex = 0; byteIndex < contextIV.length; byteIndex++) {
            iv[byteIndex] = (byte) (sequenceNumberBytes[byteIndex] ^ contextIV[byteIndex]);
        }

        encryptMessage.addAttribute(HeaderKeys.IV, iv, Attribute.DO_NOT_SEND);

        return encryptMessage;
    }

    static int getLeastSignificantBytes(byte[] source) {
        if (source.length < 4) {
            return OscoapHelper.byteArrayToInt(source);
        } else {
            // cut the sequenceNumber
            byte[] cuttedSource = new byte[3];
            System.arraycopy(source, 0, cuttedSource, 0, 3);
            return OscoapHelper.byteArrayToInt(cuttedSource);
        }
    }
}
