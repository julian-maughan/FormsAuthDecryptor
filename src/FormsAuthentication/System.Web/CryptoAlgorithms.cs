//------------------------------------------------------------------------------
// <copyright file="CryptoAlgorithms.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.Security.Cryptography;

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/CryptoAlgorithms.cs
    /// Commit hash: b31308b03e8bd5bf779fb80fda71f31eb959fe0b
    /// </remarks>
    internal static class CryptoAlgorithms
    {
        internal static Aes CreateAes()
        {
            return new AesCryptoServiceProvider();
        }

        internal static HMACSHA256 CreateHMACSHA256()
        {
            return new HMACSHA256();
        }

        internal static HMACSHA384 CreateHMACSHA384()
        {
            return new HMACSHA384();
        }

        internal static HMACSHA512 CreateHMACSHA512()
        {
            return new HMACSHA512();
        }

        internal static HMACSHA512 CreateHMACSHA512(byte[] key)
        {
            return new HMACSHA512(key);
        }
    }
}
