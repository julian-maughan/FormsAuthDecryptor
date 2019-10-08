namespace FormsAuthentication
{
    internal class DefaultMasterKeyProvider : IMasterKeyProvider
    {
        private readonly string encryptionKey;
        private readonly string validationKey;

        public DefaultMasterKeyProvider(string encryptionKey, string validationKey)
        {
            this.encryptionKey = encryptionKey;
            this.validationKey = validationKey;
        }

        public CryptographicKey GetEncryptionKey()
        {
            return new CryptographicKey(CryptoUtil.HexToBinary(encryptionKey));
        }

        public CryptographicKey GetValidationKey()
        {
            return new CryptographicKey(CryptoUtil.HexToBinary(validationKey));
        }
    }
}
