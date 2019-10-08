//------------------------------------------------------------------------------
// <copyright file="FormsAuthenticationTicketSerializer.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

using System;
using System.IO;

namespace FormsAuthentication
{
    /// <remarks>
    /// Source: https://github.com/microsoft/referencesource/blob/master/System.Web/Security/FormsAuthenticationTicketSerializer.cs
    /// Commit hash: fa352bbcac7dd189f66546297afaffc98f6a7d15
    /// </remarks>
    internal static class FormsAuthenticationTicketSerializer
    {
        private const byte CURRENT_TICKET_SERIALIZED_VERSION = 0x01;

        // Resurrects a FormsAuthenticationTicket from its serialized blob representation.
        // The input blob must be unsigned and unencrypted. This function returns null if
        // the serialized ticket format is invalid. The caller must also verify that the
        // ticket is still valid, as this method doesn't check expiration.
        public static FormsAuthenticationTicket Deserialize(byte[] serializedTicket, int serializedTicketLength)
        {
            try
            {
                using (MemoryStream ticketBlobStream = new MemoryStream(serializedTicket))
                {
                    using (SerializingBinaryReader ticketReader = new SerializingBinaryReader(ticketBlobStream))
                    {

                        // Step 1: Read the serialized format version number from the stream.
                        // Currently the only supported format is 0x01.
                        // LENGTH: 1 byte
                        byte serializedFormatVersion = ticketReader.ReadByte();
                        if (serializedFormatVersion != CURRENT_TICKET_SERIALIZED_VERSION)
                        {
                            return null; // unexpected value
                        }

                        // Step 2: Read the ticket version number from the stream.
                        // LENGTH: 1 byte
                        int ticketVersion = ticketReader.ReadByte();

                        // Step 3: Read the ticket issue date from the stream.
                        // LENGTH: 8 bytes
                        long ticketIssueDateUtcTicks = ticketReader.ReadInt64();
                        DateTime ticketIssueDateUtc = new DateTime(ticketIssueDateUtcTicks, DateTimeKind.Utc);
                        DateTime ticketIssueDateLocal = ticketIssueDateUtc.ToLocalTime();

                        // Step 4: Read the spacer from the stream.
                        // LENGTH: 1 byte
                        byte spacer = ticketReader.ReadByte();
                        if (spacer != 0xfe)
                        {
                            return null; // unexpected value
                        }

                        // Step 5: Read the ticket expiration date from the stream.
                        // LENGTH: 8 bytes
                        long ticketExpirationDateUtcTicks = ticketReader.ReadInt64();
                        DateTime ticketExpirationDateUtc = new DateTime(ticketExpirationDateUtcTicks, DateTimeKind.Utc);
                        DateTime ticketExpirationDateLocal = ticketExpirationDateUtc.ToLocalTime();

                        // Step 6: Read the ticket persistence field from the stream.
                        // LENGTH: 1 byte
                        byte ticketPersistenceFieldValue = ticketReader.ReadByte();
                        bool ticketIsPersistent;
                        switch (ticketPersistenceFieldValue)
                        {
                            case 0:
                                ticketIsPersistent = false;
                                break;
                            case 1:
                                ticketIsPersistent = true;
                                break;
                            default:
                                return null; // unexpected value
                        }

                        // Step 7: Read the ticket username from the stream.
                        // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                        string ticketName = ticketReader.ReadBinaryString();

                        // Step 8: Read the ticket custom data from the stream.
                        // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                        string ticketUserData = ticketReader.ReadBinaryString();

                        // Step 9: Read the ticket cookie path from the stream.
                        // LENGTH: 1+ bytes (7-bit encoded integer char count + UTF-16LE payload)
                        string ticketCookiePath = ticketReader.ReadBinaryString();

                        // Step 10: Read the footer from the stream.
                        // LENGTH: 1 byte
                        byte footer = ticketReader.ReadByte();
                        if (footer != 0xff)
                        {
                            return null; // unexpected value
                        }

                        // Step 11: Verify that we have consumed the entire payload.
                        // We don't expect there to be any more information after the footer.
                        // The caller is responsible for telling us when the actual payload
                        // is finished, as he may have handed us a byte array that contains
                        // the payload plus signature as an optimization, and we don't want
                        // to misinterpet the signature as a continuation of the payload.
                        if (ticketBlobStream.Position != serializedTicketLength)
                        {
                            return null;
                        }

                        // Success.
                        return FormsAuthenticationTicket.FromUtc(
                            ticketVersion /* version */,
                            ticketName /* name */,
                            ticketIssueDateUtc /* issueDateUtc */,
                            ticketExpirationDateUtc /* expirationUtc */,
                            ticketIsPersistent /* isPersistent */,
                            ticketUserData /* userData */,
                            ticketCookiePath /* cookiePath */);
                    }
                }
            }
            catch
            {
                // If anything goes wrong while parsing the token, just treat the token as invalid.
                return null;
            }
        }

        // see comments on SerializingBinaryWriter
        private sealed class SerializingBinaryReader : BinaryReader
        {
            public SerializingBinaryReader(Stream input)
                : base(input)
            {
            }

            public string ReadBinaryString()
            {
                int charCount = Read7BitEncodedInt();
                byte[] bytes = ReadBytes(charCount * 2);

                char[] chars = new char[charCount];
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = (char)(bytes[2 * i] | (bytes[2 * i + 1] << 8));
                }

                return new String(chars);
            }

            public override string ReadString()
            {
                // should never call this method since it will produce wrong results
                throw new NotImplementedException();
            }
        }
    }
}
