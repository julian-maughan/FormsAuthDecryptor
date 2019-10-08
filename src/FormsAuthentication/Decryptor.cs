namespace FormsAuthentication
{
    public enum ValidationAlgorithm
    {
        HmacSha256,
        HmacSha384,
        HmacSha512
    }

    public class Decryptor
    {
        private readonly IMasterKeyProvider _masterKeyProvider;
        private readonly DefaultCryptoAlgorithmFactory _cryptoAlgorithmFactory;
        private readonly Purpose _purpose = Purpose.FormsAuthentication_Ticket;

        public byte[] SerializedTicket { get; private set; }

        public Decryptor(string encryptionKey, string validationKey, ValidationAlgorithm algorithm)
        {
            _masterKeyProvider = new DefaultMasterKeyProvider(encryptionKey, validationKey);
            _cryptoAlgorithmFactory = new DefaultCryptoAlgorithmFactory(algorithm);
        }

        public FormsAuthenticationTicket Decrypt(string formsAuthCredential)
        {
            var derivedEncryptionKey = _purpose.GetDerivedEncryptionKey(_masterKeyProvider, SP800_108.DeriveKey);
            var derivedValidationKey = _purpose.GetDerivedValidationKey(_masterKeyProvider, SP800_108.DeriveKey);

            var cryptoService = new NetFXCryptoService(_cryptoAlgorithmFactory, derivedEncryptionKey, derivedValidationKey);

            SerializedTicket = cryptoService.Unprotect(CryptoUtil.HexToBinary(formsAuthCredential));

            return FormsAuthenticationTicketSerializer.Deserialize(SerializedTicket, SerializedTicket.Length);
        }
    }
}
