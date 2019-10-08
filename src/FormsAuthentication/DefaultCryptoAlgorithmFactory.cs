using System;
using System.Security.Cryptography;

namespace FormsAuthentication
{
    internal sealed class DefaultCryptoAlgorithmFactory : ICryptoAlgorithmFactory
    {
        private readonly ValidationAlgorithm _hashAlgorithm;

        public DefaultCryptoAlgorithmFactory(ValidationAlgorithm hashAlgorithm)
        {
            _hashAlgorithm = hashAlgorithm;
        }

        public SymmetricAlgorithm GetEncryptionAlgorithm()
        {
            return CryptoAlgorithms.CreateAes();
        }

        public KeyedHashAlgorithm GetValidationAlgorithm()
        {
            switch (_hashAlgorithm)
            {
                case ValidationAlgorithm.HmacSha256:
                    return CryptoAlgorithms.CreateHMACSHA256();
                case ValidationAlgorithm.HmacSha384:
                    return CryptoAlgorithms.CreateHMACSHA384();
                case ValidationAlgorithm.HmacSha512:
                    return CryptoAlgorithms.CreateHMACSHA512();
            }
            throw new Exception("Unsupported hash type");
        }
    }
}
