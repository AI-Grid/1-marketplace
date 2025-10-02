// SPDX-License-Identifier: MIT
#nullable enable
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using OpenSim.Modules.ContentDelivery;

namespace UuidPasswordContentDeliveryModule.Tests
{
    public sealed class PhpApiClientTests
    {
        [Test]
        public async Task AuthenticateAsync_AttachesSecretAndCorrelation()
        {
            var recordedHeaders = new Dictionary<string, string>();
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("{\"ok\":true,\"token\":\"abc\"}")
            };
            var httpClient = new RecordingHttpClient(_ => response, recordedHeaders);
            var config = new UuidPasswordContentDeliveryConfig
            {
                PhpApiBaseUrl = new Uri("https://example.test"),
                SharedSecret = "secret",
                RequestTimeoutMs = 5000,
                MaxRetries = 0,
                RateLimitBackoffMs = 10
            };

            var client = new PhpApiClient(config, httpClient);
            var result = await client.AuthenticateAsync(Guid.NewGuid().ToString(), "password123", CancellationToken.None, "corr-1");

            Assert.IsTrue(result.Ok);
            Assert.That(recordedHeaders["X-Shared-Secret"], Is.EqualTo("secret"));
            Assert.That(recordedHeaders["X-Correlation-Id"], Is.EqualTo("corr-1"));
        }

        [Test]
        public async Task AuthorizeAsync_RetriesOnTransientFailure()
        {
            var attempts = 0;
            var httpClient = new RecordingHttpClient(request =>
            {
                if (attempts++ == 0)
                {
                    throw new HttpRequestException("boom");
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"ok\":true,\"url\":\"https://example.test/download\"}")
                };
            });

            var config = new UuidPasswordContentDeliveryConfig
            {
                PhpApiBaseUrl = new Uri("https://example.test"),
                SharedSecret = string.Empty,
                MaxRetries = 1,
                RateLimitBackoffMs = 1
            };

            var client = new PhpApiClient(config, httpClient);
            var result = await client.AuthorizeAsync("token", "asset", "id", CancellationToken.None, "corr-2");

            Assert.IsTrue(result.Ok);
            Assert.That(attempts, Is.EqualTo(2));
        }

        private sealed class RecordingHttpClient : IHttpClient
        {
            private readonly Func<HttpRequestMessage, HttpResponseMessage> _responseFactory;
            private readonly IDictionary<string, string>? _headerSink;

            public RecordingHttpClient(Func<HttpRequestMessage, HttpResponseMessage> responseFactory, IDictionary<string, string>? headerSink = null)
            {
                _responseFactory = responseFactory;
                _headerSink = headerSink;
            }

            public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                if (_headerSink != null)
                {
                    foreach (var header in request.Headers)
                    {
                        _headerSink[header.Key] = string.Join(",", header.Value);
                    }
                }

                var result = _responseFactory(request);
                return Task.FromResult(result);
            }

            public void Dispose()
            {
            }
        }
    }
}
