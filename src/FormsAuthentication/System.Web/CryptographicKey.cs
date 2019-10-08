//------------------------------------------------------------------------------
// <copyright file="CryptographicKey.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/CryptographicKey.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal sealed class CryptographicKey
    {
        private readonly byte[] _keyMaterial;

        public CryptographicKey(byte[] keyMaterial)
        {
            _keyMaterial = keyMaterial;
        }

        // Returns the length of the key (in bits).
        public int KeyLength
        {
            get
            {
                return checked(_keyMaterial.Length * 8);
            }
        }

        // Returns the raw key material as a byte array.
        public byte[] GetKeyMaterial()
        {
            return _keyMaterial;
        }
    }
}
