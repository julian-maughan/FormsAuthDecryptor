//------------------------------------------------------------------------------
// <copyright file="HttpEncoderUtility.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Util/HttpEncoderUtility.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal static class HttpEncoderUtility
    {
        public static int HexToInt(char h)
        {
            return (h >= '0' && h <= '9') ? h - '0' :
            (h >= 'a' && h <= 'f') ? h - 'a' + 10 :
            (h >= 'A' && h <= 'F') ? h - 'A' + 10 :
            -1;
        }
    }
}
