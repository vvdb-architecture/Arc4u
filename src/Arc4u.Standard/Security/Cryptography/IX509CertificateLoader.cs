using System.Security.Cryptography.X509Certificates;
#if NETSTANDARD2_0
using Arc4u.Configuration;
#endif
using Microsoft.Extensions.Configuration;

namespace Arc4u.Security.Cryptography;
public interface IX509CertificateLoader
{
    public X509Certificate2 FindCertificate(CertificateInfo certificateInfo);

#if NET8_0_OR_GREATER
    public X509Certificate2 FindCertificate(CertificateFilePathInfo? certificateInfo);
#endif

    public X509Certificate2? FindCertificate(IConfiguration configuration, string sectionName);
}

public static class IX509CertificateLoaderExtensionMethods
{
    public static X509Certificate2? FindCertificate(this IX509CertificateLoader x509CertificateLoader, CertificateStoreOrFileInfo? certificateInfo)
    {
        // For this configuration, no decryption exists. Simply skip this provider.
        if (certificateInfo is null)
        {
            return null;
        }

        if (certificateInfo.Store is not null)
        {
            return x509CertificateLoader.FindCertificate(certificateInfo.Store);
        }
        else
        {
#if NET8_0_OR_GREATER
            if (certificateInfo.File is null)
            {
                throw new InvalidOperationException("No certificate information found in the configuration.");
            }
            return x509CertificateLoader.FindCertificate(certificateInfo.File);
#else
            throw new ConfigurationException("Loading a certificate from pem files are not possible in NetStandard2.0");
#endif
        }
    }
}
