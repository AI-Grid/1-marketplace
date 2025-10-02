// SPDX-License-Identifier: MIT
#nullable enable
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using log4net;

namespace OpenSim.Modules.ContentDelivery
{
#region PHP Client
    internal sealed class PhpAuthResponse
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("token")]
        public string? Token { get; set; }

        [JsonPropertyName("error_code")]
        public string? ErrorCode { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("correlation_id")]
        public string? CorrelationId { get; set; }

        [JsonPropertyName("expires_at")]
        public DateTimeOffset? ExpiresAt { get; set; }
    }

    internal sealed class PhpAuthorizeResponse
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("error_code")]
        public string? ErrorCode { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }

        [JsonPropertyName("correlation_id")]
        public string? CorrelationId { get; set; }

        [JsonPropertyName("content_type")]
        public string? ContentType { get; set; }

        [JsonPropertyName("binary")]
        public byte[]? Binary { get; set; }

        [JsonPropertyName("url")]
        public string? Url { get; set; }

        [JsonPropertyName("metadata")]
        public JsonElement Metadata { get; set; }
    }

    internal interface IHttpClient : IDisposable
    {
        Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken);
    }

    internal sealed class HttpClientWrapper : IHttpClient
    {
        private readonly HttpClient _client;
        private bool _disposed;

        public HttpClientWrapper(HttpClient client)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return _client.SendAsync(request, cancellationToken);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _client.Dispose();
            _disposed = true;
        }
    }

    internal sealed class PhpApiClient : IDisposable
    {
        private static readonly JsonSerializerOptions SerializerOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        private readonly ILog _log = LogManager.GetLogger("UuPwContentDelivery.PhpApiClient");
        private readonly UuidPasswordContentDeliveryConfig _config;
        private readonly IHttpClient _httpClient;
        private readonly Uri _authEndpoint;
        private readonly Uri _authorizeEndpoint;
        private readonly Uri _downloadEndpoint;
        private bool _disposed;

        public PhpApiClient(UuidPasswordContentDeliveryConfig config)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip
            };
            var httpClient = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromMilliseconds(_config.RequestTimeoutMs)
            };
            httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("OpenSim-ContentDelivery/1.0");
            _httpClient = new HttpClientWrapper(httpClient);
            _authEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/auth");
            _authorizeEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/authorize");
            _downloadEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/download");
        }

        internal PhpApiClient(UuidPasswordContentDeliveryConfig config, IHttpClient client)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _httpClient = client ?? throw new ArgumentNullException(nameof(client));
            _authEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/auth");
            _authorizeEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/authorize");
            _downloadEndpoint = new Uri(_config.PhpApiBaseUrl, "/api/download");
        }

        public async Task<PhpAuthResponse> AuthenticateAsync(string avatarUuid, string password, CancellationToken cancellationToken, string? correlationId = null)
        {
            var payload = new Dictionary<string, object>
            {
                ["avatar_uuid"] = avatarUuid,
                ["password"] = password
            };
            return await SendAsync<PhpAuthResponse>(_authEndpoint, payload, cancellationToken, correlationId).ConfigureAwait(false);
        }

        public async Task<PhpAuthorizeResponse> AuthorizeAsync(string token, string request, string id, CancellationToken cancellationToken, string? correlationId = null)
        {
            var payload = new Dictionary<string, object>
            {
                ["token"] = token,
                ["request"] = request,
                ["id"] = id
            };
            return await SendAsync<PhpAuthorizeResponse>(_authorizeEndpoint, payload, cancellationToken, correlationId).ConfigureAwait(false);
        }

        public async Task<HttpResponseMessage> DownloadAsync(string signedUrl, CancellationToken cancellationToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, signedUrl);
            if (!string.IsNullOrEmpty(_config.SharedSecret))
            {
                request.Headers.TryAddWithoutValidation("X-Shared-Secret", _config.SharedSecret);
            }

            return await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }

        private async Task<T> SendAsync<T>(Uri endpoint, IReadOnlyDictionary<string, object> payload, CancellationToken cancellationToken, string? correlationId)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(PhpApiClient));
            }

            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    using var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(payload, SerializerOptions), Encoding.UTF8, "application/json")
                    };

                    if (!string.IsNullOrEmpty(_config.SharedSecret))
                    {
                        request.Headers.TryAddWithoutValidation("X-Shared-Secret", _config.SharedSecret);
                    }

                    if (!string.IsNullOrEmpty(correlationId))
                    {
                        request.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
                    }

                    using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
                    var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode)
                    {
                        _log.WarnFormat("PHP API returned {0} with payload {1}", response.StatusCode, content);
                    }

                    return JsonSerializer.Deserialize<T>(content, SerializerOptions)
                           ?? throw new InvalidOperationException("Unable to deserialize PHP API response");
                }
                catch (HttpRequestException ex) when (attempt < _config.MaxRetries)
                {
                    var delay = CalculateDelay(attempt);
                    _log.WarnFormat("HTTP request failed ({0}). Retrying in {1}ms", ex.Message, delay);
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
                catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested && attempt < _config.MaxRetries)
                {
                    var delay = CalculateDelay(attempt);
                    _log.WarnFormat("HTTP request timed out. Retrying in {0}ms", delay);
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }
        }

        private TimeSpan CalculateDelay(int attempt)
        {
            var ms = (int)(_config.RateLimitBackoffMs * Math.Pow(2, attempt));
            return TimeSpan.FromMilliseconds(ms);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _httpClient.Dispose();
            _disposed = true;
        }
    }

#endregion
}
