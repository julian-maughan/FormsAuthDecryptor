//------------------------------------------------------------------------------
// <copyright file="ICryptoAlgorithmFactory.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.Security.Cryptography;

namespace FormsAuthentication
{
    /// <summary>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/ICryptoAlgorithmFactory.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </summary>
    internal interface ICryptoAlgorithmFactory
    {
        // Gets a SymmetricAlgorithm instance that can be used for encryption / decryption
        SymmetricAlgorithm GetEncryptionAlgorithm();

        // Gets a KeyedHashAlgorithm instance that can be used for signing / validation
        KeyedHashAlgorithm GetValidationAlgorithm();
    }
}
