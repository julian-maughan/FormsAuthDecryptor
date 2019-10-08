//------------------------------------------------------------------------------
// <copyright file="KeyDerivationFunction.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/KeyDerivationFunction.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal delegate CryptographicKey KeyDerivationFunction(CryptographicKey keyDerivationKey, Purpose purpose);
}