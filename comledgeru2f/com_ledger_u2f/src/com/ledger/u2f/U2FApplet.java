/*
*******************************************************************************
*   FIDO U2F Authenticator
*   (c) 2015 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*******************************************************************************
*/

package com.ledger.u2f;

import javacard.framework.*;
import javacard.security.*;
import javacardx.apdu.ExtendedLength;

public class U2FApplet extends Applet implements ExtendedLength {
    private static final byte COUNTER_COUNT = 8;
    private static final byte COUNTER_MASK = 7;

    private Counter[] counters;
    private byte next_counter;
    private byte flags;
    private Presence presence;
    private byte[] scratch;
    private byte[] attestationCertificate;
    private boolean attestationCertificateSet;
    private ECPrivateKey localPrivateKey;
    private boolean localPrivateTransient;
    private Signature attestationSignature;
    private Signature localSignature;
    private FIDOAPI fidoImpl;

    private static final byte VERSION[] = { 'U', '2', 'F', '_', 'V', '2' };

    private static final byte FIDO_INS_ENROLL = (byte)0x01;
    private static final byte FIDO_INS_SIGN = (byte)0x02;
    private static final byte FIDO_INS_VERSION = (byte)0x03;
    private static final byte ISO_INS_GET_DATA = (byte)0xC0;

    private static final byte FIDO_INS_RESET_ATTEST = (byte)0x55;

    private static final byte FIDO_ADM_SET_ATTESTATION_CERT = (byte)0x01;

    private static final byte SCRATCH_TRANSPORT_STATE = (byte)0;
    private static final byte SCRATCH_CURRENT_OFFSET = (byte)1;
    private static final byte SCRATCH_NONCERT_LENGTH = (byte)3;
    private static final byte SCRATCH_INCLUDE_CERT = (byte)5;
    private static final byte SCRATCH_SIGNATURE_LENGTH = (byte)6;
    private static final byte SCRATCH_FULL_LENGTH = (byte)8;
    private static final byte SCRATCH_PAD = (byte)10;
    // Should hold 1 (version) + 65 (public key) + 1 (key handle length) + L (key handle) + largest signature
    private static final short ENROLL_FIXED_RESPONSE_SIZE = (short)(1 + 65 + 1);    
    private static final short KEYHANDLE_MAX = (short)64; // Update if you change the KeyHandle encoding implementation
    private static final short SIGNATURE_MAX = (short)72; // DER encoding with negative R and S
    private static final short SCRATCH_PAD_SIZE = (short)(ENROLL_FIXED_RESPONSE_SIZE + KEYHANDLE_MAX + SIGNATURE_MAX); 
    private static final short SCRATCH_PUBLIC_KEY_OFFSET = (short)(SCRATCH_PAD + 1);
    private static final short SCRATCH_KEY_HANDLE_LENGTH_OFFSET = (short)(SCRATCH_PAD + 66);
    private static final short SCRATCH_KEY_HANDLE_OFFSET = (short)(SCRATCH_PAD + 67);
    private static final short SCRATCH_SIGNATURE_OFFSET = (short)(SCRATCH_PAD + ENROLL_FIXED_RESPONSE_SIZE + KEYHANDLE_MAX);

    private static final byte TRANSPORT_NONE = (byte)0;
    private static final byte TRANSPORT_EXTENDED = (byte)1;
    private static final byte TRANSPORT_NOT_EXTENDED = (byte)2;
    private static final byte TRANSPORT_NOT_EXTENDED_CERT = (byte)3;
    private static final byte TRANSPORT_NOT_EXTENDED_SIGNATURE = (byte)4;

    private static final byte P1_ENFORCE_PRESENCE_AND_SIGN = (byte)0x03;
    private static final byte P1_SIGN_CHECK_ONLY = (byte)0x07;
    private static final byte P1_IGNORE_PRESENCE_AND_SIGN = (byte)0x08;

    private static final byte ENROLL_LEGACY_VERSION = (byte)0x05;
    private static final byte RFU_ENROLL_SIGNED_VERSION[] = { (byte)0x00 };

    private static final short ENROLL_PUBLIC_KEY_OFFSET = (short)1;
    private static final short ENROLL_KEY_HANDLE_LENGTH_OFFSET = (short)66;
    private static final short ENROLL_KEY_HANDLE_OFFSET = (short)67;
    private static final short APDU_CHALLENGE_OFFSET = (short)0;
    private static final short APDU_APPLICATION_PARAMETER_OFFSET = (short)32;

    private static final short FIDO_SW_TEST_OF_PRESENCE_REQUIRED = ISO7816.SW_CONDITIONS_NOT_SATISFIED;
    private static final short FIDO_SW_INVALID_KEY_HANDLE = ISO7816.SW_WRONG_DATA;

    private static final byte INSTALL_FLAG_DISABLE_USER_PRESENCE = (byte)0x01;
    private static final byte INSTALL_FLAG_ALLOW_RESET_ATTEST = (byte)0x02;

    // Parameters
    // 1 byte : flags
    // 2 bytes big endian short : length of attestation certificate
    // 32 bytes : private attestation key
    public U2FApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        if (parametersLength != 35) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Initialize with 8 counters.
        counters = new Counter[] {
            new Counter(), new Counter(),
            new Counter(), new Counter(),
            new Counter(), new Counter(),
            new Counter(), new Counter()
        };

        // First counter is counter zero.
        next_counter = 0;

        scratch = JCSystem.makeTransientByteArray((short)(SCRATCH_PAD + SCRATCH_PAD_SIZE), JCSystem.CLEAR_ON_DESELECT);

        try {
            // ok, let's save RAM
            localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256, false);
            localPrivateTransient = true;
        }
        catch(CryptoException e) {
            try {
                // ok, let's save a bit less RAM
                localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET, KeyBuilder.LENGTH_EC_FP_256, false);
                localPrivateTransient = true;
            }
            catch(CryptoException e1) {
                // ok, let's test the flash wear leveling \o/
                localPrivateKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
                Secp256r1.setCommonCurveParameters(localPrivateKey);
            }
        }

        attestationSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        localSignature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        flags = parameters[parametersOffset];

        if ((flags & INSTALL_FLAG_DISABLE_USER_PRESENCE) == 0) {
            presence = new OneShotPresence();
        } else {
            presence = new NullPresence();
        }

        attestationCertificate = new byte[Util.getShort(parameters, (short)(parametersOffset + 1))];

        // Set up our attestation signature object.
        ECPrivateKey attestationPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256r1.setCommonCurveParameters(attestationPrivateKey);
        attestationPrivateKey.setS(parameters, (short)(parametersOffset + 3), (short)32);
        attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);

        fidoImpl = new FIDOStandalone();
    }

    private void handleSetAttestationCert(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        short copyOffset = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
        if ((short)(copyOffset + len) > (short)attestationCertificate.length) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        Util.arrayCopy(buffer, dataOffset, attestationCertificate, copyOffset, len);
        if ((short)(copyOffset + len) == (short)attestationCertificate.length) {
            attestationCertificateSet = true;
        }
    }

    private static boolean isProtocolContactless(byte protocol) {
        switch ((byte) (protocol & APDU.PROTOCOL_MEDIA_MASK)) {
            case APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A:
            case APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B:
            case -80: // APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_F
                return true;
            default:
                return false;
        }
    }

    // Typical calibration values:
    //
    //  * J3R3xx: 24
    //  * J3H145: 19
    //
    private static final byte securityDelayCalibration = 19;
    private void securityDelay(short ds) {
        // Busy work.
        for (; ds != 0 ; ds--) {
			for (byte i1 = securityDelayCalibration; i1 != 0 ; i1--) {
				for (byte i2 = (byte)0x80; i2 != 0 ; i2--) {
				}
			}
        }
    }

    private void handleResetAttest(APDU apdu) {
        if ((flags & INSTALL_FLAG_ALLOW_RESET_ATTEST) == 0) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();

        if (len != 34) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        if (isProtocolContactless(APDU.getProtocol())) {
            // Force a delay of 10 seconds.
            securityDelay((short)100);
        }

        JCSystem.beginTransaction();
        {
            short certLen = Util.getShort(buffer, dataOffset);
            if (certLen != (short) attestationCertificate.length) {
                attestationCertificate = new byte[Util.getShort(buffer, dataOffset)];
            }
            attestationCertificateSet = false;

            // Set up our attestation signature object.
            ECPrivateKey attestationPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            Secp256r1.setCommonCurveParameters(attestationPrivateKey);
            attestationPrivateKey.setS(buffer, (short) (dataOffset + 2), (short) 32);
            attestationSignature.init(attestationPrivateKey, Signature.MODE_SIGN);
        }
        JCSystem.commitTransaction();

        JCSystem.requestObjectDeletion();
    }

    private void handleEnroll(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);

        // The length of this command must always be 64 bytes.
        if (len != 64) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Deny if user presence cannot be validated
        presence.enforce_user_presence();

        // Generate the key pair
        short keyHandleLength = fidoImpl.generateKeyAndWrap(
            buffer,
            (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET),
            scratch,
            SCRATCH_PUBLIC_KEY_OFFSET,
            scratch,
            SCRATCH_KEY_HANDLE_OFFSET,
            (byte)(next_counter++ & COUNTER_MASK)
        );

        scratch[SCRATCH_PAD] = ENROLL_LEGACY_VERSION;
        scratch[SCRATCH_KEY_HANDLE_LENGTH_OFFSET] = (byte)keyHandleLength;

        // Prepare the attestation
        attestationSignature.update(RFU_ENROLL_SIGNED_VERSION, (short)0, (short)1);
        attestationSignature.update(buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), (short)32);
        attestationSignature.update(buffer, (short)(dataOffset + APDU_CHALLENGE_OFFSET), (short)32);
        attestationSignature.update(scratch, SCRATCH_KEY_HANDLE_OFFSET, keyHandleLength);
        attestationSignature.update(scratch, SCRATCH_PUBLIC_KEY_OFFSET, (short)65);

        short signatureSize = attestationSignature.sign(buffer, (short)0, (short)0, scratch, SCRATCH_SIGNATURE_OFFSET);
        short outOffset = (short)(ENROLL_PUBLIC_KEY_OFFSET + 65 + 1 + keyHandleLength);

        if (extendedLength) {
            // If using extended length, the message can be completed and sent immediately
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)(outOffset + attestationCertificate.length + signatureSize));
            apdu.sendBytesLong(scratch, SCRATCH_PAD, outOffset);
            apdu.sendBytesLong(attestationCertificate, (short)0, (short)attestationCertificate.length);
            apdu.sendBytesLong(scratch, SCRATCH_SIGNATURE_OFFSET, signatureSize);
        }
        else {
            // Otherwise, keep the signature and proceed to send the first chunk
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, (short)0);
            Util.setShort(scratch, SCRATCH_SIGNATURE_LENGTH, signatureSize);
            Util.setShort(scratch, SCRATCH_NONCERT_LENGTH, outOffset);
            Util.setShort(scratch, SCRATCH_FULL_LENGTH, (short)(outOffset + attestationCertificate.length + signatureSize));
            scratch[SCRATCH_INCLUDE_CERT] = (byte)1;
            handleGetData(apdu);
        }
    }

    private void handleSign(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short len = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata();
        byte p1 = buffer[ISO7816.OFFSET_P1];
        boolean sign = false;
        boolean enforce_presence = false;
        short keyHandleLength;
        boolean extendedLength = (dataOffset != ISO7816.OFFSET_CDATA);
        short outOffset = SCRATCH_PAD;

        if (len < 65) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        switch(p1) {
            case P1_ENFORCE_PRESENCE_AND_SIGN:
                sign = true;
                enforce_presence = true;
                break;
            case P1_IGNORE_PRESENCE_AND_SIGN:
                sign = true;
                break;
            case P1_SIGN_CHECK_ONLY:
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        if (localPrivateTransient) {
            Secp256r1.setCommonCurveParameters(localPrivateKey);
        }

        keyHandleLength = (short)(buffer[(short)(dataOffset + 64)] & 0xff);

        // Verify key handle, unwrap our private
        // key, and get our counter index. This
        // will throw a ISO7816.SW_WRONG_DATA if
        // the key handle is bad.
        byte counter_index = fidoImpl.unwrap(
            buffer, (short)(dataOffset + 65), keyHandleLength,
            buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET),
            (sign ? localPrivateKey : null)
        );

        // If not signing, return with the "correct" exception
        if (!sign) {
            ISOException.throwIt(FIDO_SW_TEST_OF_PRESENCE_REQUIRED);
        }

        if (enforce_presence) {
            // This will either wait for user presence to be
            // asserted or throw ISO7816.SW_CONDITIONS_NOT_SATISFIED.
            scratch[outOffset++] = presence.enforce_user_presence();
        } else {
            // This version returns immediately and never
            // throws an exception. The returned value will
            // indicate user presence if it makes sense for
            // this authenticator.
            scratch[outOffset++] = presence.check_user_presence();
        }

        // Increase the signature counter and write it to scratch
        Counter counter = counters[counter_index & COUNTER_MASK];
        counter.inc();
        outOffset = counter.writeValue(scratch, outOffset);

        // Create our signature.
        localSignature.init(localPrivateKey, Signature.MODE_SIGN);
        localSignature.update(buffer, (short)(dataOffset + APDU_APPLICATION_PARAMETER_OFFSET), (short)32);
        localSignature.update(scratch, SCRATCH_PAD, (short)5);
        outOffset += localSignature.sign(buffer, (short)(dataOffset + APDU_CHALLENGE_OFFSET), (short)32, scratch, outOffset);

        if (extendedLength) {
            // If using extended length, the message can be completed and sent immediately
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            apdu.setOutgoing();
            apdu.setOutgoingLength((short)(outOffset - SCRATCH_PAD));
            apdu.sendBytesLong(scratch, SCRATCH_PAD, (short)(outOffset - SCRATCH_PAD));
        }
        else {
            // Otherwise send the first chunk
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, (short)0);
            Util.setShort(scratch, SCRATCH_SIGNATURE_LENGTH, (short)0);
            Util.setShort(scratch, SCRATCH_NONCERT_LENGTH, (short)(outOffset - SCRATCH_PAD));
            Util.setShort(scratch, SCRATCH_FULL_LENGTH, (short)(outOffset - SCRATCH_PAD));
            scratch[SCRATCH_INCLUDE_CERT] = (byte)0;
            handleGetData(apdu);
        }
    }

    private void handleVersion(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
        apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
    }

    private void handleGetData(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short currentOffset = Util.getShort(scratch, SCRATCH_CURRENT_OFFSET);
        short fullLength = Util.getShort(scratch, SCRATCH_FULL_LENGTH);
        switch(scratch[SCRATCH_TRANSPORT_STATE]) {
            case TRANSPORT_NOT_EXTENDED:
            case TRANSPORT_NOT_EXTENDED_CERT:
            case TRANSPORT_NOT_EXTENDED_SIGNATURE:
                break;
            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        short requestedSize = apdu.setOutgoing();
        short outOffset = (short)0;

        if (requestedSize == 0) {
            requestedSize = (short)buffer.length;
            if (requestedSize > 0xFF) {
                requestedSize = 256;
            }
        }

        if (scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED) {
            short dataSize = Util.getShort(scratch, SCRATCH_NONCERT_LENGTH);
            short blockSize = ((short)(dataSize - currentOffset) > requestedSize ? requestedSize : (short)(dataSize - currentOffset));
            Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_PAD + currentOffset), buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
            if (currentOffset == dataSize) {
                if (scratch[SCRATCH_INCLUDE_CERT] == (byte)1) {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED_CERT;
                    currentOffset = (short)0;
                    requestedSize -= blockSize;                    
                }
                else {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;
                }
            }
        }
        if ((scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED_CERT) && (requestedSize != (short)0)) {
            short blockSize = ((short)(attestationCertificate.length - currentOffset) > requestedSize ? requestedSize : (short)(attestationCertificate.length - currentOffset));
            Util.arrayCopyNonAtomic(attestationCertificate, currentOffset, buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
            if (currentOffset == (short)attestationCertificate.length) {
                if (Util.getShort(scratch, SCRATCH_SIGNATURE_LENGTH) != (short)0) {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED_SIGNATURE;
                    currentOffset = (short)0;
                    requestedSize -= blockSize;                
                }
                else {
                    scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;   
                }
            }
        }
        if ((scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED_SIGNATURE) && (requestedSize != (short)0)) {
            short signatureSize = Util.getShort(scratch, SCRATCH_SIGNATURE_LENGTH);
            short blockSize = ((short)(signatureSize - currentOffset) > requestedSize ? requestedSize : (short)(signatureSize - currentOffset));
            Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_SIGNATURE_OFFSET + currentOffset), buffer, outOffset, blockSize);
            outOffset += blockSize;
            currentOffset += blockSize;
            fullLength -= blockSize;
        }                
        apdu.setOutgoingLength(outOffset);
        apdu.sendBytes((short)0, outOffset);        
        Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, currentOffset);
        Util.setShort(scratch, SCRATCH_FULL_LENGTH, fullLength);
        if (fullLength > 256) {
            ISOException.throwIt(ISO7816.SW_BYTES_REMAINING_00);
        }
        else 
        if (fullLength != 0) {
            ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 + fullLength));   
        }
    }

    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            if (attestationCertificateSet) {
                Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
                apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
            }
            return;
        }

        if (!attestationCertificateSet) {
            if ((buffer[ISO7816.OFFSET_CLA] & (byte)0x80) == (byte)0x80
                    && buffer[ISO7816.OFFSET_INS] == FIDO_ADM_SET_ATTESTATION_CERT
            ) {
                handleSetAttestationCert(apdu);
            } else if ((buffer[ISO7816.OFFSET_CLA] & (byte)0x80) == (byte)0x00
                    && buffer[ISO7816.OFFSET_INS] == FIDO_INS_RESET_ATTEST
            ) {
                handleResetAttest(apdu);
            } else {
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
            return;
        }

        if ((buffer[ISO7816.OFFSET_CLA] & (byte)0x80) == (byte)0x80) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        } else {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case FIDO_INS_ENROLL:
                    handleEnroll(apdu);
                    break;
                case FIDO_INS_SIGN:
                    handleSign(apdu);
                    break;
                case FIDO_INS_VERSION:
                    handleVersion(apdu);
                    break;
                case ISO_INS_GET_DATA:
                    handleGetData(apdu);
                    break;
                case FIDO_INS_RESET_ATTEST:
                    handleResetAttest(apdu);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    public static void install (byte bArray[], short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short)(bArray[offset] + 1); // instance
        offset += (short)(bArray[offset] + 1); // privileges
        new U2FApplet(bArray, (short)(offset + 1), bArray[offset]).register(bArray, (short)(bOffset + 1), bArray[bOffset]);
    }
}
