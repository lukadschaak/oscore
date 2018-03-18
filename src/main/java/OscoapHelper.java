import COSE.*;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.*;

import javax.xml.bind.DatatypeConverter;
import java.util.Base64;

/**
 * Some helper methods like converting hex to byte[].
 * Also helping stuff for cose
 * Created by Luka Dschaak on 07.05.2017.
 */
public class OscoapHelper {

    public static String reducedIPv6Host(String host) {
        return host.replace("[","").replace("]", "");
    }

    public static boolean isInteger(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if(Character.digit(s.charAt(i),10) < 0) return false;
        }
        return true;
    }

    public static void debugLogMessage(org.eclipse.californium.core.coap.Message message) {
        if (message != null) {
            if (message instanceof Response) {
                System.out.println( Utils.prettyPrint( ((Response) message) ) );
            } else if (message instanceof Request) {
                System.out.println( Utils.prettyPrint( ((Request) message) ) );
            }
        } else {
            System.out.println("No message received.");
        }
    }

    static int byteArrayToInt(byte[] b)
    {
        int result = 0;

        if (b.length > 3) {
            result = result | ((b[3] & 0xFF) << 24);
        }
        if (b.length > 2) {
            result = result | ((b[2] & 0xFF) << 16);
        }
        if (b.length > 1) {
            result = result | ((b[1] & 0xFF) << 8);
        }
        if (b.length > 0) {
            result = result | (b[0] & 0xFF);
        }

        return result;
    }

    /**
     * Converts an int into a reduced byte array. Int is interpreted in Big-Endian.
     * Lowest array index contains high value bits and vice versa.
     * Reduced means, return only the necessary bytes. Example: if the value is smaller
     * than 256, an array with only one byte is returned.
     * For compression of the COSE object (section 8 of OSCOAP draft), the sequence number
     * is required as byte array.
     * This method does both at the same time with native operations as possible for Java.
     *
     * @param value non negative int
     * @return the transformed int, new byte[1] for int = 0, null for negative int
     */
    static byte[] getReducedByteArray(int value) {
        if (value < 0) {
            return null;
        }
        byte[] result;

        if (value > 16777215) {
            result = new byte[4];
        } else if (value > 65535) {
            result = new byte[3];
        } else if (value > 255) {
            result = new byte[2];
        } else {
            // even if the value is == 0, the minimum is one empty byte
            result = new byte[1];
        }


        if ((value >> 24) > 0) {
            result[3] = (byte) (value >> 24);
        }
        if ((value >> 16) > 0) {
            result[2] = (byte) (value >> 16);
        }
        if ((value >> 8) > 0) {
            result[1] = (byte) (value >> 8);
        }
        // do this always, even if value == 0
        result[0] = (byte) value;

        return result;
    }

    static byte[] getBytesFromHexMinusNotation(String hexWithMinus) {
        String[] hexValues = hexWithMinus.split("-");

        byte[] resultBytes = new byte[hexValues.length];

        for (int i = 0; i < hexValues.length; i++) {
            String hex = hexValues[i];
            resultBytes[i] = DatatypeConverter.parseHexBinary(hex)[0];
        }

        return resultBytes;
    }

    /**
     * In the test cases this is context B
     * @return the context
     */
    static CommonContext getSecurityContextForServerDefault(String host) {
        // Common
        AlgorithmID algorithm = AlgorithmID.AES_CCM_64_64_128;
        String hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23";
        byte[] masterSecret = OscoapHelper.getBytesFromHexMinusNotation(hex);


        // Context B

        CommonContext cc2 = new CommonContext(algorithm, masterSecret, null, host);

        String senderIDString = "73-65-72-76-65-72";
        byte[] senderID = OscoapHelper.getBytesFromHexMinusNotation(senderIDString);
        String senderKeyString = "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6D";
        byte[] senderKey = OscoapHelper.getBytesFromHexMinusNotation(senderKeyString);
        String senderIVString = "20-75-0B-95-F9-78-C8";
        byte[] senderIV = OscoapHelper.getBytesFromHexMinusNotation(senderIVString);
        SenderContext sc2 = new SenderContext(senderID, senderKey, senderIV);
        cc2.setSenderContext(sc2);

        String recipientIDString = "63-6C-69-65-6E-74";
        byte[] recipientID = OscoapHelper.getBytesFromHexMinusNotation(recipientIDString);
        String recipientKeyString = "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-48";
        byte[] recipientKey = OscoapHelper.getBytesFromHexMinusNotation(recipientKeyString);
        String recipientIVString = "01-53-DD-FE-DE-44-19";
        byte[] recipientIV = OscoapHelper.getBytesFromHexMinusNotation(recipientIVString);
        RecipientContext rc2 = new RecipientContext(recipientID, recipientKey, recipientIV);

        cc2.setRecipientContext(rc2);

        return cc2;
    }

    static CommonContext getSecurityContextForClientDefault(String host) {
        // Common
        AlgorithmID algorithm = AlgorithmID.AES_CCM_64_64_128;
        String hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23";
        byte[] masterSecret = OscoapHelper.getBytesFromHexMinusNotation(hex);


        // Context A

        CommonContext cc1 = new CommonContext(algorithm, masterSecret, null, host);

        String senderIDString = "63-6C-69-65-6E-74";
        byte[] senderID = OscoapHelper.getBytesFromHexMinusNotation(senderIDString);
        String senderKeyString = "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-48";
        byte[] senderKey = OscoapHelper.getBytesFromHexMinusNotation(senderKeyString);
        String senderIVString = "01-53-DD-FE-DE-44-19";
        byte[] senderIV = OscoapHelper.getBytesFromHexMinusNotation(senderIVString);
        SenderContext sc1 = new SenderContext(senderID, senderKey, senderIV);
        cc1.setSenderContext(sc1);

        String recipientIDString = "73-65-72-76-65-72";
        byte[] recipientID = OscoapHelper.getBytesFromHexMinusNotation(recipientIDString);
        String recipientKeyString = "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6D";
        byte[] recipientKey = OscoapHelper.getBytesFromHexMinusNotation(recipientKeyString);
        String recipientIVString = "20-75-0B-95-F9-78-C8";
        byte[] recipientIV = OscoapHelper.getBytesFromHexMinusNotation(recipientIVString);
        RecipientContext rc1 = new RecipientContext(recipientID, recipientKey, recipientIV);

        cc1.setRecipientContext(rc1);

        return cc1;
    }

    static CommonContext getSecurityContextForClientFalseSenderID(String host) {
        // Common
        AlgorithmID algorithm = AlgorithmID.AES_CCM_64_64_128;
        String hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23";
        byte[] masterSecret = OscoapHelper.getBytesFromHexMinusNotation(hex);


        // Context A

        CommonContext cc1 = new CommonContext(algorithm, masterSecret, null, host);

        String senderIDString = "63-6C-69-65-6E-75";
            // correct would be "63-6C-69-65-6E-74"
        byte[] senderID = OscoapHelper.getBytesFromHexMinusNotation(senderIDString);
        String senderKeyString = "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-48";
        byte[] senderKey = OscoapHelper.getBytesFromHexMinusNotation(senderKeyString);
        String senderIVString = "01-53-DD-FE-DE-44-19";
        byte[] senderIV = OscoapHelper.getBytesFromHexMinusNotation(senderIVString);
        SenderContext sc1 = new SenderContext(senderID, senderKey, senderIV);
        cc1.setSenderContext(sc1);

        String recipientIDString = "73-65-72-76-65-72";
        byte[] recipientID = OscoapHelper.getBytesFromHexMinusNotation(recipientIDString);
        String recipientKeyString = "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6D";
        byte[] recipientKey = OscoapHelper.getBytesFromHexMinusNotation(recipientKeyString);
        String recipientIVString = "20-75-0B-95-F9-78-C8";
        byte[] recipientIV = OscoapHelper.getBytesFromHexMinusNotation(recipientIVString);
        RecipientContext rc1 = new RecipientContext(recipientID, recipientKey, recipientIV);

        cc1.setRecipientContext(rc1);

        return cc1;
    }

    static CommonContext getSecurityContextForClientFalseSenderKey(String host) {
        // Common
        AlgorithmID algorithm = AlgorithmID.AES_CCM_64_64_128;
        String hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23";
        byte[] masterSecret = OscoapHelper.getBytesFromHexMinusNotation(hex);


        // Context A

        CommonContext cc1 = new CommonContext(algorithm, masterSecret, null, host);

        String senderIDString = "63-6C-69-65-6E-74";
        byte[] senderID = OscoapHelper.getBytesFromHexMinusNotation(senderIDString);
        String senderKeyString = "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-49";
            // correct would be  "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-48";
        byte[] senderKey = OscoapHelper.getBytesFromHexMinusNotation(senderKeyString);
        String senderIVString = "01-53-DD-FE-DE-44-19";
        byte[] senderIV = OscoapHelper.getBytesFromHexMinusNotation(senderIVString);
        SenderContext sc1 = new SenderContext(senderID, senderKey, senderIV);
        cc1.setSenderContext(sc1);

        String recipientIDString = "73-65-72-76-65-72";
        byte[] recipientID = OscoapHelper.getBytesFromHexMinusNotation(recipientIDString);
        String recipientKeyString = "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6D";
        byte[] recipientKey = OscoapHelper.getBytesFromHexMinusNotation(recipientKeyString);
        String recipientIVString = "20-75-0B-95-F9-78-C8";
        byte[] recipientIV = OscoapHelper.getBytesFromHexMinusNotation(recipientIVString);
        RecipientContext rc1 = new RecipientContext(recipientID, recipientKey, recipientIV);

        cc1.setRecipientContext(rc1);

        return cc1;
    }

    static CommonContext getSecurityContextForClientFalseRecipientKey(String host) {
        // Common
        AlgorithmID algorithm = AlgorithmID.AES_CCM_64_64_128;
        String hex = "01-02-03-04-05-06-07-08-09-0A-0B-0C-0D-0E-0F-10-11-12-13-14-15-16-17-18-19-1A-1B-1C-1D-1E-1F-20-21-22-23";
        byte[] masterSecret = OscoapHelper.getBytesFromHexMinusNotation(hex);


        // Context A

        CommonContext cc1 = new CommonContext(algorithm, masterSecret, null, host);

        String senderIDString = "63-6C-69-65-6E-74";
        byte[] senderID = OscoapHelper.getBytesFromHexMinusNotation(senderIDString);
        String senderKeyString = "21-64-42-DA-60-3C-51-59-2D-F4-C3-D0-CD-1D-0D-48";
        byte[] senderKey = OscoapHelper.getBytesFromHexMinusNotation(senderKeyString);
        String senderIVString = "01-53-DD-FE-DE-44-19";
        byte[] senderIV = OscoapHelper.getBytesFromHexMinusNotation(senderIVString);
        SenderContext sc1 = new SenderContext(senderID, senderKey, senderIV);
        cc1.setSenderContext(sc1);

        String recipientIDString = "73-65-72-76-65-72";
        byte[] recipientID = OscoapHelper.getBytesFromHexMinusNotation(recipientIDString);
        String recipientKeyString = "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6E";
            // correct would be     "D5-CB-37-10-37-15-34-A1-CA-22-4E-19-EB-96-E9-6D"
        byte[] recipientKey = OscoapHelper.getBytesFromHexMinusNotation(recipientKeyString);
        String recipientIVString = "20-75-0B-95-F9-78-C8";
        byte[] recipientIV = OscoapHelper.getBytesFromHexMinusNotation(recipientIVString);
        RecipientContext rc1 = new RecipientContext(recipientID, recipientKey, recipientIV);

        cc1.setRecipientContext(rc1);

        return cc1;
    }

    static void SetAttributes(Attribute msg, CBORObject cnAttributes, int which, boolean fPublicKey) throws Exception {
        if (cnAttributes == null) return;

        CBORObject cnKey;
        CBORObject cnValue;

        for (CBORObject attr : cnAttributes.getKeys()) {
            switch (attr.AsString()) {
                case "alg":
                    cnKey = HeaderKeys.Algorithm.AsCBOR();
                    cnValue = AlgorithmMap(cnAttributes.get(attr));
                    break;

                case "kid":
                    cnKey= HeaderKeys.KID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "spk_kid":
                    cnKey = HeaderKeys.ECDH_SKID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "IV_hex":
                    cnKey = HeaderKeys.IV.AsCBOR();
                    cnValue = CBORObject.FromObject(OscoapHelper.hexStringToByteArray(cnAttributes.get(attr).AsString()));
                    break;

                case "partialIV_hex":
                    cnKey = HeaderKeys.PARTIAL_IV.AsCBOR();
                    cnValue = CBORObject.FromObject(OscoapHelper.hexStringToByteArray(cnAttributes.get(attr).AsString()));
                    break;

                case "salt":
                    cnKey = HeaderKeys.HKDF_Salt.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apu_id":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_ID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apv_id":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_ID.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apu_nonce":
                case "apu_nonce_hex":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_nonce.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apv_nonce":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_nonce.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apu_other":
                    cnKey = HeaderKeys.HKDF_Context_PartyU_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "apv_other":
                    cnKey = HeaderKeys.HKDF_Context_PartyV_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "pub_other":
                    cnKey = HeaderKeys.HKDF_SuppPub_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "priv_other":
                    cnKey = HeaderKeys.HKDF_SuppPriv_Other.AsCBOR();
                    cnValue = CBORObject.FromObject(cnAttributes.get(attr).AsString().getBytes());
                    break;

                case "ctyp":
                    cnKey = HeaderKeys.CONTENT_TYPE.AsCBOR();
                    cnValue = cnAttributes.get(attr);
                    break;

//                case "crit":
//                    cnKey = HeaderKeys.CriticalHeaders.AsCBOR();
//                    cnValue = CBORObject.NewArray();
//                    for (CBORObject x : cnAttributes.get(attr).getValues()) {
//                        cnValue.Add(HeaderMap(x));
//                    }
//                    break;

                case "reserved":
                    cnKey = attr;
                    cnValue = cnAttributes.get(attr);
                    break;

                case "epk":
                    cnKey = null;
                    cnValue = null;
                    break;

                default:
                    throw new Exception("Attribute " + attr.AsString() + " is not part of SetAttributes");
            }

            if (cnKey != null) {
                msg.addAttribute(cnKey, cnValue, which);
            }
        }
    }

    static CBORObject AlgorithmMap(CBORObject old)
    {
        if (old.getType() == CBORType.Number) {
            return old;
        }

        switch (old.AsString()) {
            case "A128GCM": return AlgorithmID.AES_GCM_128.AsCBOR();
            case "A192GCM": return AlgorithmID.AES_GCM_192.AsCBOR();
            case "A256GCM": return AlgorithmID.AES_GCM_256.AsCBOR();
            case "A128KW": return AlgorithmID.AES_KW_128.AsCBOR();
            case "A192KW": return AlgorithmID.AES_KW_192.AsCBOR();
            case "A256KW": return AlgorithmID.AES_KW_256.AsCBOR();
            // case "RSA-OAEP": return AlgorithmID.RSA_OAEP.AsCBOR();
            // case "RSA-OAEP-256": return AlgorithmID.RSA_OAEP_256.AsCBOR();
            case "HS256": return AlgorithmID.HMAC_SHA_256.AsCBOR();
            case "HS256/64": return AlgorithmID.HMAC_SHA_256_64.AsCBOR();
            case "HS384": return AlgorithmID.HMAC_SHA_384.AsCBOR();
            case "HS512": return AlgorithmID.HMAC_SHA_512.AsCBOR();
            case "ES256": return AlgorithmID.ECDSA_256.AsCBOR();
            case "ES384": return AlgorithmID.ECDSA_384.AsCBOR();
            case "ES512": return AlgorithmID.ECDSA_512.AsCBOR();
            // case "PS256": return AlgorithmID.RSA_PSS_256.AsCBOR();
            // case "PS512": return AlgorithmID.RSA_PSS_512.AsCBOR();
            case "direct": return AlgorithmID.Direct.AsCBOR();
            //case "AES-CMAC-128/64": return AlgorithmID.AES_CMAC_128_64.AsCBOR();
            //case "AES-CMAC-256/64": return AlgorithmID.AES_CMAC_256_64.AsCBOR();
            case "AES-MAC-128/64": return AlgorithmID.AES_CBC_MAC_128_64.AsCBOR();
            case "AES-MAC-256/64": return AlgorithmID.AES_CBC_MAC_256_64.AsCBOR();
            case "AES-MAC-128/128": return AlgorithmID.AES_CBC_MAC_128_128.AsCBOR();
            case "AES-MAC-256/128": return AlgorithmID.AES_CBC_MAC_256_128.AsCBOR();
            case "AES-CCM-16-128/64": return AlgorithmID.AES_CCM_16_64_128.AsCBOR();
            case "AES-CCM-16-128/128": return AlgorithmID.AES_CCM_16_128_128.AsCBOR();
            case "AES-CCM-16-256/64": return AlgorithmID.AES_CCM_16_64_256.AsCBOR();
            case "AES-CCM-16-256/128": return AlgorithmID.AES_CCM_16_128_256.AsCBOR();
            case "AES-CCM-64-128/64": return AlgorithmID.AES_CCM_64_64_128.AsCBOR();
            case "AES-CCM-64-128/128": return AlgorithmID.AES_CCM_64_128_128.AsCBOR();
            case "AES-CCM-64-256/64": return AlgorithmID.AES_CCM_64_64_256.AsCBOR();
            case "AES-CCM-64-256/128": return AlgorithmID.AES_CCM_64_128_256.AsCBOR();
            case "HKDF-HMAC-SHA-256": return AlgorithmID.HKDF_HMAC_SHA_256.AsCBOR();
            case "HKDF-HMAC-SHA-512": return AlgorithmID.HKDF_HMAC_SHA_512.AsCBOR();
            case "HKDF-AES-128": return AlgorithmID.HKDF_HMAC_AES_128.AsCBOR();
            case "HKDF-AES-256": return AlgorithmID.HKDF_HMAC_AES_256.AsCBOR();
            case "ECDH-ES": return AlgorithmID.ECDH_ES_HKDF_256.AsCBOR();
            case "ECDH-ES-512": return AlgorithmID.ECDH_ES_HKDF_512.AsCBOR();
            case "ECDH-SS": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
            case "ECDH-SS-256": return AlgorithmID.ECDH_SS_HKDF_256.AsCBOR();
            case "ECDH-SS-512": return AlgorithmID.ECDH_SS_HKDF_512.AsCBOR();
            case "ECDH-ES+A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
            case "ECDH-SS+A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
            case "ECDH-ES-A128KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_128.AsCBOR();
            case "ECDH-SS-A128KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_128.AsCBOR();
            case "ECDH-ES-A192KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_192.AsCBOR();
            case "ECDH-SS-A192KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_192.AsCBOR();
            case "ECDH-ES-A256KW": return AlgorithmID.ECDH_ES_HKDF_256_AES_KW_256.AsCBOR();
            case "ECDH-SS-A256KW": return AlgorithmID.ECDH_SS_HKDF_256_AES_KW_256.AsCBOR();

            default: return old;
        }
    }

    public static OneKey BuildKey(CBORObject keyIn, boolean fPublicKey) throws CoseException {
        CBORObject cnKeyOut = CBORObject.NewMap();

        for (CBORObject key : keyIn.getKeys()) {
            CBORObject cnValue = keyIn.get(key);

            switch (key.AsString()) {
                case "kty":
                    switch (cnValue.AsString()) {
                        case "EC":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(2));
                            break;

                        case "oct":
                            cnKeyOut.set(CBORObject.FromObject(1), CBORObject.FromObject(4));
                            break;
                    }
                    break;

                case "crv":
                    switch (cnValue.AsString()) {
                        case "P-256":
                            cnValue = CBORObject.FromObject(1);
                            break;

                        case "P-384":
                            cnValue = CBORObject.FromObject(2);
                            break;

                        case "P-521":
                            cnValue = CBORObject.FromObject(3);
                            break;
                    }


                    cnKeyOut.set(CBORObject.FromObject(-1), cnValue);
                    break;

                case "x":
                    cnKeyOut.set(KeyKeys.EC2_X.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;

                case "y":
                    cnKeyOut.set(KeyKeys.EC2_Y.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;

                case "d":
                    if (!fPublicKey) {
                        cnKeyOut.set(KeyKeys.EC2_D.AsCBOR(), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    }
                    break;

                case "k":
                    cnKeyOut.set(CBORObject.FromObject(-1), CBORObject.FromObject(Base64.getUrlDecoder().decode(cnValue.AsString())));
                    break;
            }
        }

        return new OneKey( cnKeyOut);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
