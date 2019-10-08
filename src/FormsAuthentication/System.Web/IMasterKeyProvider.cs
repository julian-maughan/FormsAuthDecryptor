//------------------------------------------------------------------------------
// <copyright file="IMasterKeyProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace FormsAuthentication
{
    /// <summary>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/IMasterKeyProvider.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </summary>
    internal interface IMasterKeyProvider
    {
        // encryption + decryption key
        CryptographicKey GetEncryptionKey();

        // signing + validation key
        CryptographicKey GetValidationKey();
    }
}
