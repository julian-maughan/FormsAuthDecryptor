//------------------------------------------------------------------------------
// <copyright file="Purpose.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.IO;

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/Purpose.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal sealed class Purpose
    {
        // predefined purposes
        public static readonly Purpose FormsAuthentication_Ticket = new Purpose("FormsAuthentication.Ticket");

        public readonly string PrimaryPurpose;
        public readonly string[] SpecificPurposes;

        private byte[] _derivedKeyLabel;
        private byte[] _derivedKeyContext;

        public Purpose(string primaryPurpose, params string[] specificPurposes)
            : this(primaryPurpose, specificPurposes, null, null)
        {
        }

        // ctor for unit testing
        internal Purpose(string primaryPurpose, string[] specificPurposes, CryptographicKey derivedEncryptionKey, CryptographicKey derivedValidationKey)
        {
            PrimaryPurpose = primaryPurpose;
            SpecificPurposes = specificPurposes ?? new string[0];
            DerivedEncryptionKey = derivedEncryptionKey;
            DerivedValidationKey = derivedValidationKey;
            SaveDerivedKeys = (SpecificPurposes.Length == 0);
        }

        // The cryptographic keys that were derived from this Purpose.
        internal CryptographicKey DerivedEncryptionKey { get; private set; }
        internal CryptographicKey DerivedValidationKey { get; private set; }

        // Whether the derived key should be saved back to this Purpose object by the ICryptoService,
        // e.g. because this Purpose will be used over and over again. We assume that any built-in
        // Purpose object that is passed without any specific purposes is intended for repeated use,
        // hence the ICryptoService will try to cache cryptographic keys as a performance optimization.
        // If specific purposes have been specified, they were likely generated at runtime, hence it
        // is not appropriate for the keys to be cached in this instance.
        internal bool SaveDerivedKeys { get; set; }

        public CryptographicKey GetDerivedEncryptionKey(IMasterKeyProvider masterKeyProvider, KeyDerivationFunction keyDerivationFunction)
        {
            // has a key already been stored?
            CryptographicKey actualDerivedKey = DerivedEncryptionKey;
            if (actualDerivedKey == null)
            {
                CryptographicKey masterKey = masterKeyProvider.GetEncryptionKey();
                actualDerivedKey = keyDerivationFunction(masterKey, this);

                // only save the key back to storage if this Purpose is configured to do so
                if (SaveDerivedKeys)
                {
                    DerivedEncryptionKey = actualDerivedKey;
                }
            }

            return actualDerivedKey;
        }

        public CryptographicKey GetDerivedValidationKey(IMasterKeyProvider masterKeyProvider, KeyDerivationFunction keyDerivationFunction)
        {
            // has a key already been stored?
            CryptographicKey actualDerivedKey = DerivedValidationKey;
            if (actualDerivedKey == null)
            {
                CryptographicKey masterKey = masterKeyProvider.GetValidationKey();
                actualDerivedKey = keyDerivationFunction(masterKey, this);

                // only save the key back to storage if this Purpose is configured to do so
                if (SaveDerivedKeys)
                {
                    DerivedValidationKey = actualDerivedKey;
                }
            }

            return actualDerivedKey;
        }

        // Returns a label and context suitable for passing into the SP800-108 KDF.
        internal void GetKeyDerivationParameters(out byte[] label, out byte[] context)
        {
            // The primary purpose can just be used as the label directly, since ASP.NET
            // is always in full control of the primary purpose (it's never user-specified).
            if (_derivedKeyLabel == null)
            {
                _derivedKeyLabel = CryptoUtil.SecureUTF8Encoding.GetBytes(PrimaryPurpose);
            }

            // The specific purposes (which can contain nonce, identity, etc.) are concatenated
            // together to form the context. The BinaryWriter class prepends each element with
            // a 7-bit encoded length to guarantee uniqueness.
            if (_derivedKeyContext == null)
            {
                using (MemoryStream stream = new MemoryStream())
                using (BinaryWriter writer = new BinaryWriter(stream, CryptoUtil.SecureUTF8Encoding))
                {
                    foreach (string specificPurpose in SpecificPurposes)
                    {
                        writer.Write(specificPurpose);
                    }
                    _derivedKeyContext = stream.ToArray();
                }
            }

            label = _derivedKeyLabel;
            context = _derivedKeyContext;
        }
    }
}
