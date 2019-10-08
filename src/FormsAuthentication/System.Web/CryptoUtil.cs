//------------------------------------------------------------------------------
// <copyright file="CryptoUtil.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System.Runtime.CompilerServices;
using System.Text;

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/Cryptography/CryptoUtil.cs
    /// Commit hash: 74eb1593e09a636270482f1c0525aabdccb1f364
    /// </remarks>
    internal static class CryptoUtil
    {
        /// <summary>
        /// Similar to Encoding.UTF8, but throws on invalid bytes. Useful for security routines where we need
        /// strong guarantees that we're always producing valid UTF8 streams.
        /// </summary>
        public static readonly UTF8Encoding SecureUTF8Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// Converts a byte array into its hexadecimal representation.
        /// </summary>
        /// <param name="data">The binary byte array.</param>
        /// <returns>The hexadecimal (uppercase) equivalent of the byte array.</returns>
        public static string BinaryToHex(byte[] data)
        {
            if (data == null)
            {
                return null;
            }

            char[] hex = new char[checked(data.Length * 2)];

            for (int i = 0; i < data.Length; i++)
            {
                byte thisByte = data[i];
                hex[2 * i] = NibbleToHex((byte)(thisByte >> 4)); // high nibble
                hex[2 * i + 1] = NibbleToHex((byte)(thisByte & 0xf)); // low nibble
            }

            return new string(hex);
        }

        // Determines if two buffer instances are equal, e.g. whether they contain the same payload. This method
        // is written in such a manner that it should take the same amount of time to execute regardless of
        // whether the result is success or failure. The modulus operation is intended to make the check take the
        // same amount of time, even if the buffers are of different lengths.
        // Use bit-wise integer operations (instead of if/conditional or boolean
        // operations) to prevent compiler optimizations and to keep consistent time
        // spent in each iteration.
        //
        // !! DO NOT CHANGE THIS METHOD WITHOUT SECURITY
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool BuffersAreEqual(byte[] buffer1, int buffer1Offset, int buffer1Count, byte[] buffer2, int buffer2Offset, int buffer2Count)
        {
            //Debug.ValidateArrayBounds(buffer1, buffer1Offset, buffer1Count);
            //Debug.ValidateArrayBounds(buffer2, buffer2Offset, buffer2Count);

            if (buffer1Count != buffer2Count)
                return false;

            int success = 0;
            unchecked
            {
                for (int i = 0; i < buffer1Count; i++)
                {
                    success = success | (buffer1[buffer1Offset + i] - buffer2[buffer2Offset + i]);
                }
            }
            return (0 == success);
        }

        /// <summary>
        /// Converts a hexadecimal string into its binary representation.
        /// </summary>
        /// <param name="data">The hex string.</param>
        /// <returns>The byte array corresponding to the contents of the hex string,
        /// or null if the input string is not a valid hex string.</returns>
        public static byte[] HexToBinary(string data)
        {
            if (data == null || data.Length % 2 != 0)
            {
                // input string length is not evenly divisible by 2
                return null;
            }

            byte[] binary = new byte[data.Length / 2];

            for (int i = 0; i < binary.Length; i++)
            {
                int highNibble = HttpEncoderUtility.HexToInt(data[2 * i]);
                int lowNibble = HttpEncoderUtility.HexToInt(data[2 * i + 1]);

                if (highNibble == -1 || lowNibble == -1)
                {
                    return null; // bad hex data
                }
                binary[i] = (byte)((highNibble << 4) | lowNibble);
            }

            return binary;
        }

        // converts a nibble (4 bits) to its uppercase hexadecimal character representation [0-9, A-F]
        private static char NibbleToHex(byte nibble)
        {
            return (char)((nibble < 10) ? (nibble + '0') : (nibble - 10 + 'A'));
        }
    }
}
