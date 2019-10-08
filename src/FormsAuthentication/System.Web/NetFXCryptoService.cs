//------------------------------------------------------------------------------
// <copyright file="NetFXCryptoService.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/NetFXCryptoService.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal sealed class NetFXCryptoService // : ICryptoService
    {
        private readonly ICryptoAlgorithmFactory _cryptoAlgorithmFactory;
        private readonly CryptographicKey _encryptionKey;
        private readonly bool _predictableIV;
        private readonly CryptographicKey _validationKey;

        public NetFXCryptoService(ICryptoAlgorithmFactory cryptoAlgorithmFactory, CryptographicKey encryptionKey, CryptographicKey validationKey, bool predictableIV = false)
        {
            _cryptoAlgorithmFactory = cryptoAlgorithmFactory;
            _encryptionKey = encryptionKey;
            _validationKey = validationKey;
            _predictableIV = predictableIV;
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            // The entire operation is wrapped in a 'checked' block because any overflows should be treated as failures.
            checked
            {

                // We want to check that the input is in the form:
                // protectedData := IV || Enc(Kenc, IV, clearData) || Sign(Kval, IV || Enc(Kenc, IV, clearData))

                // Definitions used in this method:
                // encryptedPayload := Enc(Kenc, IV, clearData)
                // signature := Sign(Kval, IV || encryptedPayload)

                // These SymmetricAlgorithm instances are single-use; we wrap it in a 'using' block.
                using (SymmetricAlgorithm decryptionAlgorithm = _cryptoAlgorithmFactory.GetEncryptionAlgorithm())
                {
                    decryptionAlgorithm.Key = _encryptionKey.GetKeyMaterial();

                    // These KeyedHashAlgorithm instances are single-use; we wrap it in a 'using' block.
                    using (KeyedHashAlgorithm validationAlgorithm = _cryptoAlgorithmFactory.GetValidationAlgorithm())
                    {
                        validationAlgorithm.Key = _validationKey.GetKeyMaterial();

                        // First, we need to verify that protectedData is even long enough to contain
                        // the required components (IV, encryptedPayload, signature).

                        int ivByteCount = decryptionAlgorithm.BlockSize / 8; // IV length is equal to the block size
                        int signatureByteCount = validationAlgorithm.HashSize / 8;
                        int encryptedPayloadByteCount = protectedData.Length - ivByteCount - signatureByteCount;
                        if (encryptedPayloadByteCount <= 0)
                        {
                            // protectedData doesn't meet minimum length requirements
                            return null;
                        }

                        // If that check passes, we need to detect payload tampering.

                        // Compute the signature over the IV and encrypted payload
                        // computedSignature := Sign(Kval, IV || encryptedPayload)
                        byte[] computedSignature = validationAlgorithm.ComputeHash(protectedData, 0, ivByteCount + encryptedPayloadByteCount);

                        if (!CryptoUtil.BuffersAreEqual(
                            buffer1: protectedData, buffer1Offset: ivByteCount + encryptedPayloadByteCount, buffer1Count: signatureByteCount,
                            buffer2: computedSignature, buffer2Offset: 0, buffer2Count: computedSignature.Length))
                        {

                            // the computed signature didn't match the incoming signature, which is a sign of payload tampering
                            return null;
                        }

                        // At this point, we're certain that we generated the signature over this payload,
                        // so we can go ahead with decryption.

                        // Populate the IV from the incoming stream
                        byte[] iv = new byte[ivByteCount];
                        Buffer.BlockCopy(protectedData, 0, iv, 0, iv.Length);
                        decryptionAlgorithm.IV = iv;

                        // Write the decrypted payload to the memory stream.
                        using (MemoryStream memStream = new MemoryStream())
                        {
                            using (ICryptoTransform decryptor = decryptionAlgorithm.CreateDecryptor())
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Write))
                                {
                                    cryptoStream.Write(protectedData, ivByteCount, encryptedPayloadByteCount);
                                    cryptoStream.FlushFinalBlock();

                                    // At this point
                                    // memStream := clearData

                                    byte[] clearData = memStream.ToArray();
                                    return clearData;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
