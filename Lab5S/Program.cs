using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace Lab5S;

public class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("1. Генерация сертификатов...");

        var caCert = GenerateCaCertificate();
        var serverCert = GenerateCertificate(caCert, "localhost", true);
        var validClientCert = GenerateCertificate(caCert, "backend-01", false);
        var hackerClientCert = GenerateCertificate(caCert, "evil-hacker", false);

        Console.WriteLine("Сертификаты успешно сгенерированы.\n");

        var serverTask = StartServerAsync(serverCert, caCert);

        await Task.Delay(1000);

        Console.WriteLine("\n--- Тестирование подключений ---");

        Console.WriteLine("\n[Тест 1] Подключение с сертификатом CN=backend-01...");
        await RunClientAsync(validClientCert, caCert, "backend-01");

        Console.WriteLine("\n[Тест 2] Подключение с сертификатом CN=evil-hacker...");
        await RunClientAsync(hackerClientCert, caCert, "evil-hacker");

        Console.WriteLine("\nТестирование завершено. Нажмите Ctrl+C для выхода.");
        await serverTask;
    }

    #region Настройка Сервера
    static Task StartServerAsync(X509Certificate2 serverCert, X509Certificate2 caCert)
    {
        var builder = WebApplication.CreateBuilder();

        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ListenLocalhost(5001, listenOptions =>
            {
                listenOptions.UseHttps(httpsOptions =>
                {
                    httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                    httpsOptions.ServerCertificate = serverCert;

                    httpsOptions.ClientCertificateValidation = (cert, chain, errors) =>
                    {
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.Clear();
                        chain.ChainPolicy.CustomTrustStore.Add(caCert);
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown;

                        if (!chain.Build(cert))
                        {
                            Console.WriteLine("   [Сервер] Отказ: Сертификат клиента не прошел проверку цепочки (не от нашего CA).");
                            return false;
                        }

                        var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                        if (cn != null && (cn.StartsWith("backend-") || cn.StartsWith("monitoring-")))
                        {
                            Console.WriteLine($"   [Сервер] Успех: Клиент с CN={cn} прошел проверку Name Constraints.");
                            return true;
                        }

                        Console.WriteLine($"   [Сервер] Отказ: Клиент с CN={cn} отвергнут (Name Constraints mismatch).");
                        return false;
                    };
                });
            });
        });

        var app = builder.Build();
        app.MapGet("/", () => "Доступ разрешен! Секретные данные сервера.");
        return app.RunAsync();
    }
    #endregion

    #region Настройка Клиента
    static async Task RunClientAsync(X509Certificate2 clientCert, X509Certificate2 caCert, string clientName)
    {
        var handler = new HttpClientHandler();

        handler.ClientCertificates.Add(clientCert);

        handler.ServerCertificateCustomValidationCallback = (request, cert, chain, errors) =>
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Clear();
            chain.ChainPolicy.CustomTrustStore.Add(caCert);
            return chain.Build(cert);
        };

        using var client = new HttpClient(handler);
        try
        {
            var response = await client.GetAsync("https://localhost:5001");
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            Console.WriteLine($"   [Клиент {clientName}] Ответ от сервера: {content}");
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException || ex.InnerException is IOException)
        {
            Console.WriteLine($"   [Клиент {clientName}] Соединение разорвано! Ошибка TLS рукопожатия.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"   [Клиент {clientName}] Ошибка: {ex.Message}");
        }
    }
    #endregion

    #region Генерация сертификатов (CA, Server, Client)
    static X509Certificate2 GenerateCaCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=MyTestCA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));
        return ExportToPfx(cert);
    }

    static X509Certificate2 GenerateCertificate(X509Certificate2 caCert, string commonName, bool isServer)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={commonName}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));

        var oid = isServer ? "1.3.6.1.5.5.7.3.1" : "1.3.6.1.5.5.7.3.2";
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(oid) }, true));

        if (isServer)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(commonName);
            request.CertificateExtensions.Add(sanBuilder.Build());
        }

        var cert = request.Create(caCert, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1), Guid.NewGuid().ToByteArray());
        cert = cert.CopyWithPrivateKey(rsa);

        return ExportToPfx(cert);
    }

    static X509Certificate2 ExportToPfx(X509Certificate2 cert)
    {
        var pfxBytes = cert.Export(X509ContentType.Pfx);
        return new X509Certificate2(pfxBytes, (string)null, X509KeyStorageFlags.Exportable);
    }
    #endregion
}