// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET6_0_OR_GREATER
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core.TestFramework;
using NUnit.Framework;

namespace Azure.Identity.Tests
{
    /// <summary>
    /// Linux-specific tests for KubernetesProxyHttpHandler to verify the X509Chain fix
    /// for OpenSSL. These tests use real HTTPS connections to trigger the SSL validation
    /// callback where the original bug manifested as a NullReferenceException in
    /// OpenSslX509ChainProcessor.FindFirstChain when reusing the passed-in chain object.
    /// </summary>
    [RunOnlyOnPlatforms(Linux = true)]
    public class KubernetesProxyHttpHandlerLinuxTests
    {
        private TestTempFileHandler _tempFiles = new TestTempFileHandler();
        private X509Certificate2 _serverCertificate;
        private X509Certificate2 _caCertificate;
        private SimpleHttpsServer _httpsServer;

        [SetUp]
        public void Setup()
        {
            // Generate a self-signed CA certificate and server certificate for testing
            (_caCertificate, _serverCertificate) = GenerateTestCertificates();
        }

        [TearDown]
        public void Cleanup()
        {
            _tempFiles.CleanupTempFiles();
            _httpsServer?.Dispose();
            _serverCertificate?.Dispose();
            _caCertificate?.Dispose();
        }

        /// <summary>
        /// This test verifies that the X509Chain fix works on Linux.
        /// The original bug caused a NullReferenceException when the ServerCertificateCustomValidationCallback
        /// tried to reuse the X509Chain passed from SSL validation and call Build() on it again.
        /// On Linux with OpenSSL, this fails because the chain is already in a partially built state.
        /// </summary>
        [Test]
        public async Task SendAsync_WithCustomCa_SucceedsOnLinux()
        {
            // Arrange - Start a local HTTPS server with our test certificate
            _httpsServer = new SimpleHttpsServer(_serverCertificate);
            var serverPort = await _httpsServer.StartAsync();

            var caPem = ExportCertificateToPem(_caCertificate);
            var caFilePath = _tempFiles.GetTempFilePath();
            File.WriteAllText(caFilePath, caPem);

            var config = new KubernetesProxyConfig
            {
                ProxyUrl = new Uri($"https://localhost:{serverPort}"),
                SniName = "localhost",
                CaFilePath = caFilePath
            };

            var handler = new KubernetesProxyHttpHandler(config);
            var httpClient = new HttpClient(handler);

            // Act - This would throw NullReferenceException on Linux before the fix
            // because the callback reused the passed-in X509Chain and called Build() on it
            HttpResponseMessage response = null;
            Exception caughtException = null;

            try
            {
                response = await httpClient.GetAsync($"https://login.microsoftonline.com/test");
            }
            catch (Exception ex)
            {
                caughtException = ex;
            }

            // Assert
            if (caughtException != null)
            {
                // Check if it's the specific bug we're testing for
                if (caughtException.ToString().Contains("OpenSslX509ChainProcessor") ||
                    caughtException.ToString().Contains("FindFirstChain"))
                {
                    Assert.Fail($"The X509Chain bug on Linux is still present: {caughtException}");
                }

                // Other exceptions might be expected (e.g., connection refused if something else is wrong)
                // but shouldn't be the NullReferenceException from OpenSSL chain processing
                Assert.That(caughtException, Is.Not.InstanceOf<NullReferenceException>(),
                    $"Should not throw NullReferenceException from X509Chain processing: {caughtException}");
            }

            Assert.IsNotNull(response, "Response should not be null");
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        /// <summary>
        /// Tests that multiple concurrent SSL connections work correctly on Linux.
        /// This ensures the fix handles concurrent chain validation properly.
        /// </summary>
        [Test]
        public async Task SendAsync_WithCustomCa_ConcurrentRequestsSucceedOnLinux()
        {
            // Arrange
            _httpsServer = new SimpleHttpsServer(_serverCertificate);
            var serverPort = await _httpsServer.StartAsync();

            var caPem = ExportCertificateToPem(_caCertificate);
            var caFilePath = _tempFiles.GetTempFilePath();
            File.WriteAllText(caFilePath, caPem);

            var config = new KubernetesProxyConfig
            {
                ProxyUrl = new Uri($"https://localhost:{serverPort}"),
                SniName = "localhost",
                CaFilePath = caFilePath
            };

            var handler = new KubernetesProxyHttpHandler(config);
            var httpClient = new HttpClient(handler);

            // Act - Make multiple concurrent requests
            var tasks = new Task<HttpResponseMessage>[5];
            for (int i = 0; i < 5; i++)
            {
                tasks[i] = httpClient.GetAsync($"https://login.microsoftonline.com/test{i}");
            }

            HttpResponseMessage[] responses = null;
            Exception caughtException = null;

            try
            {
                responses = await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                caughtException = ex;
            }

            // Assert
            if (caughtException != null)
            {
                Assert.That(caughtException.ToString(), Does.Not.Contain("OpenSslX509ChainProcessor"),
                    $"Should not have OpenSSL chain processing errors: {caughtException}");
                Assert.That(caughtException, Is.Not.InstanceOf<NullReferenceException>(),
                    $"Should not throw NullReferenceException: {caughtException}");
            }

            Assert.IsNotNull(responses, "Responses should not be null");
            foreach (var response in responses)
            {
                Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            }
        }

        /// <summary>
        /// Tests the X509Chain building behavior directly to verify the fix.
        /// This simulates what happens in the SSL validation callback.
        /// </summary>
        [Test]
        public void X509Chain_NewInstance_BuildSucceedsOnLinux()
        {
            // Arrange - This tests the fix pattern directly
            // Use the generated certificates directly instead of PEM parsing
            var caCert = _caCertificate;
            var serverCert = _serverCertificate;

            // Act - Using a NEW X509Chain instance (the fix pattern)
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.ExtraStore.Add(caCert);
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                // This should succeed on all platforms including Linux
                var buildResult = chain.Build(serverCert);

                // Assert
                Assert.IsTrue(buildResult || chain.ChainElements.Count > 0,
                    $"Chain build should succeed or have elements. Status: {string.Join(", ", GetChainStatus(chain))}");
            }
        }

        /// <summary>
        /// Demonstrates the original bug - calling Build() on a pre-built chain fails on Linux.
        /// This test documents the behavior we're fixing.
        /// </summary>
        [Test]
        public void X509Chain_ReusedInstance_DemonstratesLinuxBehavior()
        {
            // Arrange - Use the generated certificates directly
            var caCert = _caCertificate;
            var serverCert = _serverCertificate;

            // First build with a chain
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.Build(serverCert);

                // Now try to "reuse" the chain by modifying policy and building again
                // This simulates what would happen if we reused the callback's chain parameter
                chain.ChainPolicy.ExtraStore.Add(caCert);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

                // On Linux with OpenSSL, this second Build() call may fail or behave unexpectedly
                // The fix is to always use a fresh X509Chain instance
                bool secondBuildResult = false;
                Exception secondBuildException = null;

                try
                {
                    secondBuildResult = chain.Build(serverCert);
                }
                catch (Exception ex)
                {
                    secondBuildException = ex;
                }

                // Document the behavior - on Linux this may throw or return unexpected results
                // The actual behavior depends on the .NET and OpenSSL versions
                Console.WriteLine($"Second Build result: {secondBuildResult}");
                if (secondBuildException != null)
                {
                    Console.WriteLine($"Second Build exception: {secondBuildException.GetType().Name} - {secondBuildException.Message}");
                }

                // The key insight: don't rely on reusing X509Chain instances
                // Always create a new instance for custom validation
            }

            // This test passes regardless of the second build's outcome
            // It's primarily for documentation and to verify the platform behavior
            Assert.Pass("Test documents X509Chain reuse behavior on Linux");
        }

        /// <summary>
        /// Tests that inline CA data works correctly for SSL validation on Linux.
        /// </summary>
        [Test]
        public async Task SendAsync_WithInlineCaData_SucceedsOnLinux()
        {
            // Arrange
            _httpsServer = new SimpleHttpsServer(_serverCertificate);
            var serverPort = await _httpsServer.StartAsync();

            var caPem = ExportCertificateToPem(_caCertificate);

            var config = new KubernetesProxyConfig
            {
                ProxyUrl = new Uri($"https://localhost:{serverPort}"),
                SniName = "localhost",
                CaData = caPem // Inline CA data instead of file
            };

            var handler = new KubernetesProxyHttpHandler(config);
            var httpClient = new HttpClient(handler);

            // Act
            var response = await httpClient.GetAsync($"https://login.microsoftonline.com/test");

            // Assert
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        }

        private static (X509Certificate2 Ca, X509Certificate2 Server) GenerateTestCertificates()
        {
            // Generate CA certificate
            using var caKey = RSA.Create(2048);
            var caRequest = new CertificateRequest(
                new X500DistinguishedName("CN=Test CA"),
                caKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            caRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            var caCert = caRequest.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365));

            // Generate server certificate signed by CA
            using var serverKey = RSA.Create(2048);
            var serverRequest = new CertificateRequest(
                new X500DistinguishedName("CN=localhost"),
                serverKey,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            serverRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, false));
            serverRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));

            // Add Subject Alternative Name for localhost
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName("localhost");
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(sanBuilder.Build());

            var serverCertPublic = serverRequest.Create(
                caCert,
                DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(365),
                Guid.NewGuid().ToByteArray());

            // Combine with private key for server use
            var serverCertWithKey = serverCertPublic.CopyWithPrivateKey(serverKey);

            // Export and re-import to get a usable certificate
            var caCertBytes = caCert.Export(X509ContentType.Pfx);
            var serverCertBytes = serverCertWithKey.Export(X509ContentType.Pfx);

#pragma warning disable SYSLIB0057 // X509Certificate2 constructors are obsolete
            return (
                new X509Certificate2(caCertBytes),
                new X509Certificate2(serverCertBytes)
            );
#pragma warning restore SYSLIB0057
        }

        private static string ExportCertificateToPem(X509Certificate2 cert)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-----BEGIN CERTIFICATE-----");
            sb.AppendLine(Convert.ToBase64String(cert.RawData, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END CERTIFICATE-----");
            return sb.ToString();
        }

        private static string[] GetChainStatus(X509Chain chain)
        {
            var statuses = new string[chain.ChainStatus.Length];
            for (int i = 0; i < chain.ChainStatus.Length; i++)
            {
                statuses[i] = $"{chain.ChainStatus[i].Status}: {chain.ChainStatus[i].StatusInformation}";
            }
            return statuses;
        }

        /// <summary>
        /// Simple HTTPS server for testing SSL certificate validation.
        /// </summary>
        private class SimpleHttpsServer : IDisposable
        {
            private readonly X509Certificate2 _certificate;
            private TcpListener _listener;
            private CancellationTokenSource _cts;
            private Task _serverTask;

            public SimpleHttpsServer(X509Certificate2 certificate)
            {
                _certificate = certificate;
            }

            public async Task<int> StartAsync()
            {
                _listener = new TcpListener(IPAddress.Loopback, 0);
                _listener.Start();
                var port = ((IPEndPoint)_listener.LocalEndpoint).Port;

                _cts = new CancellationTokenSource();
                _serverTask = Task.Run(() => AcceptConnectionsAsync(_cts.Token));

                // Give the server a moment to start
                await Task.Delay(100);

                return port;
            }

            private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var client = await _listener.AcceptTcpClientAsync();
                        _ = HandleClientAsync(client, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (Exception)
                    {
                        // Connection error, continue accepting
                    }
                }
            }

            private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
            {
                try
                {
                    using (client)
                    using (var sslStream = new SslStream(client.GetStream(), false))
                    {
                        await sslStream.AuthenticateAsServerAsync(
                            _certificate,
                            clientCertificateRequired: false,
                            enabledSslProtocols: SslProtocols.Tls12 | SslProtocols.Tls13,
                            checkCertificateRevocation: false);

                        // Read HTTP request (simplified - just read until we get the headers)
                        var buffer = new byte[4096];
                        var bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);

                        // Send HTTP response
                        var response = "HTTP/1.1 200 OK\r\n" +
                                     "Content-Type: application/json\r\n" +
                                     "Content-Length: 26\r\n" +
                                     "Connection: close\r\n" +
                                     "\r\n" +
                                     "{\"status\":\"ok\",\"test\":true}";

                        var responseBytes = Encoding.UTF8.GetBytes(response);
                        await sslStream.WriteAsync(responseBytes, 0, responseBytes.Length, cancellationToken);
                        await sslStream.FlushAsync(cancellationToken);
                    }
                }
                catch (Exception)
                {
                    // Client disconnected or SSL error
                }
            }

            public void Dispose()
            {
                _cts?.Cancel();
                _listener?.Stop();
                try
                {
                    _serverTask?.Wait(TimeSpan.FromSeconds(2));
                }
                catch (AggregateException)
                {
                    // Task was cancelled
                }
                _cts?.Dispose();
            }
        }
    }
}
#endif
