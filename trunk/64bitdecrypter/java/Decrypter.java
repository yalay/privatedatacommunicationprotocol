// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Decrypter is sample code showing the steps to decrypt and verify 64-bit
// values. It uses the Base 64 decoder from the Apache commons project
// (http://commons.apache.org).

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * An Exception thrown by Decrypter if the ciphertext cannot successfully be
 * decrypted.
 */
class DecrypterException extends Exception {
  public DecrypterException(String message) {
    super(message);
  }
}

/**
 * Java language sample code for 64 bit value decryption
 */
public class Decrypter {
  /** The length of the initialization vector */
  private static final int INITIALIZATION_VECTOR_SIZE = 16;
  /** The length of the ciphertext */
  private static final int CIPHERTEXT_SIZE = 8;
  /** The length of the signature */
  private static final int SIGNATURE_SIZE = 4;

  /**
   * Converts from unpadded web safe base 64 encoding (RFC 3548) to standard
   * base 64 encoding (RFC 2045) and pads the result.
   */
  public static String unWebSafeAndPad(String webSafe) {
    String pad = "";
    if ((webSafe.length() % 4) == 2) {
      pad = "==";
    } else if ((webSafe.length() % 4) == 1) {
      pad = "=";
    }
    return webSafe.replace('-', '+').replace('_', '/') + pad;
  }

  /**
   * Performs the decryption algorithm.
   */
  public static byte[] decrypt(byte[] initializationVector,
                               byte[] ciphertext,
                               byte[] signature,
                               SecretKey encryptionKey,
                               SecretKey integrityKey)
      throws DecrypterException {
    byte[] plaintext = new byte[CIPHERTEXT_SIZE];
    try {
      // Decrypt the value
      Mac encryptionHmac = Mac.getInstance("HmacSHA1");
      encryptionHmac.init(encryptionKey);
      byte[] encryptionPad = encryptionHmac.doFinal(initializationVector);
      for (int i = 0; i < plaintext.length; i++) {
        plaintext[i] = (byte) (ciphertext[i] ^ encryptionPad[i]);
      }

      // Compute the signature
      Mac integrityHmac = Mac.getInstance("HmacSHA1");
      integrityHmac.init(integrityKey);
      integrityHmac.update(plaintext);
      integrityHmac.update(initializationVector);
      byte[] computedSignature = new byte[SIGNATURE_SIZE];
      System.arraycopy(integrityHmac.doFinal(), 0, computedSignature, 0,
          computedSignature.length);
      if (!Arrays.equals(signature, computedSignature)) {
        throw new DecrypterException("Signature mismatch.");
      }
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("HmacSHA1 not supported.", e);
    } catch (InvalidKeyException e) {
      throw new RuntimeException("Key is invalid for this purpose.", e);
    }
    return plaintext;
  }

  /**
   * Parses the timestamp out of the initialization vector. Note: this method
   * loses precision. java.util.Date only holds the date to millisecond
   * precision while the initialization vector contains a timestamp with
   * microsecond precision.
   */
  public static Date getTimeFromInitializationVector(
      byte[] initializationVector) {
    ByteBuffer buffer = ByteBuffer.wrap(initializationVector);
    long seconds = buffer.getInt();
    long micros = buffer.getInt();
    return new Date((seconds * 1000) + (micros / 1000));
  }

  /**
   * Uses hardcoded keys to decrypt an example encoded ciphertext string.
   */
  public static void main(String[] args)
      throws IOException, UnsupportedEncodingException {
    byte[] encryptionKeyBytes = {
        (byte) 0xb0, (byte) 0x8c, (byte) 0x70, (byte) 0xcf, (byte) 0xbc,
        (byte) 0xb0, (byte) 0xeb, (byte) 0x6c, (byte) 0xab, (byte) 0x7e,
        (byte) 0x82, (byte) 0xc6, (byte) 0xb7, (byte) 0x5d, (byte) 0xa5,
        (byte) 0x20, (byte) 0x72, (byte) 0xae, (byte) 0x62, (byte) 0xb2,
        (byte) 0xbf, (byte) 0x4b, (byte) 0x99, (byte) 0x0b, (byte) 0xb8,
        (byte) 0x0a, (byte) 0x48, (byte) 0xd8, (byte) 0x14, (byte) 0x1e,
        (byte) 0xec, (byte) 0x07
    };
    byte[] integrityKeyBytes = {
        (byte) 0xbf, (byte) 0x77, (byte) 0xec, (byte) 0x55, (byte) 0xc3,
        (byte) 0x01, (byte) 0x30, (byte) 0xc1, (byte) 0xd8, (byte) 0xcd,
        (byte) 0x18, (byte) 0x62, (byte) 0xed, (byte) 0x2a, (byte) 0x4c,
        (byte) 0xd2, (byte) 0xc7, (byte) 0x6a, (byte) 0xc3, (byte) 0x3b,
        (byte) 0xc0, (byte) 0xc4, (byte) 0xce, (byte) 0x8a, (byte) 0x3d,
        (byte) 0x3b, (byte) 0xbd, (byte) 0x3a, (byte) 0xd5, (byte) 0x68,
        (byte) 0x77, (byte) 0x92
    };
    String websafeB64EncodedCiphertext = "SjpvRwAB4kB7jEpgW5IA8p73ew9ic6VZpFsPnA";
    String b64EncodedCiphertext = unWebSafeAndPad(websafeB64EncodedCiphertext);

    // Base 64 decode using Apache commons library. You should replace this
    // with whatever you use internally.
    byte[] codeString = Base64.decodeBase64(
        b64EncodedCiphertext.getBytes("US-ASCII"));

    byte[] initializationVector = new byte[INITIALIZATION_VECTOR_SIZE];
    System.arraycopy(codeString, 0, initializationVector, 0,
        initializationVector.length);
    byte[] ciphertext = new byte[CIPHERTEXT_SIZE];
    System.arraycopy(codeString, initializationVector.length, ciphertext, 0,
        ciphertext.length);
    byte[] signature = new byte[SIGNATURE_SIZE];
    System.arraycopy(codeString, initializationVector.length + ciphertext.length,
        signature, 0, signature.length);

    byte[] plaintext;
    SecretKey encryptionKey = new SecretKeySpec(encryptionKeyBytes, "HmacSHA1");
    SecretKey integrityKey = new SecretKeySpec(integrityKeyBytes, "HmacSHA1");
    try {
      plaintext = decrypt(initializationVector, ciphertext, signature,
          encryptionKey, integrityKey);
    } catch (DecrypterException e) {
      System.err.println("Failed to decode ciphertext. " + e.getMessage());
      return;
    }
    DataInputStream dis = new DataInputStream(
        new ByteArrayInputStream(plaintext));
    long value = dis.readLong();
    Date timestamp = getTimeFromInitializationVector(initializationVector);
    System.out.println("The value is: " + value + " generated on "
        + DateFormat.getDateTimeInstance().format(timestamp) + " + "
        + timestamp.getTime() % 1000);
    System.out.println("    Expected: 709959680 generated on "
        + "Jun 18, 2009 12:45:59 PM + 123");
  }
}
