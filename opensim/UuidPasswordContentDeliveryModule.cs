// SPDX-License-Identifier: MIT
#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using log4net;
using OpenMetaverse;
using OpenSim.Framework;
using OpenSim.Framework.Servers.HttpServer;
using OpenSim.Region.Framework.Interfaces;
using OpenSim.Region.Framework.Scenes;

namespace OpenSim.Modules.ContentDelivery
{
#region Config
    /// <summary>
    /// Module configuration as read from OpenSim.ini.
    /// </summary>
    internal sealed class UuidPasswordContentDeliveryConfig
    {
        private const string Section = "UuidPasswordContentDelivery";

        public bool Enabled { get; init; }
        public Uri PhpApiBaseUrl { get; init; } = new("https://localhost");
        public string SharedSecret { get; init; } = string.Empty;
        public int RequestTimeoutMs { get; init; } = 5000;
        public int MaxRetries { get; init; } = 2;
        public bool ProxyBinary { get; init; }
        public int RateLimitBackoffMs { get; init; } = 500;
        public string LoggingLevel { get; init; } = "INFO";

        public static UuidPasswordContentDeliveryConfig From(IConfigSource source)
        {
            if (source == null) throw new ArgumentNullException(nameof(source));
            var config = source.Configs[Section];
            if (config == null)
            {
                return new UuidPasswordContentDeliveryConfig { Enabled = false };
            }

            return new UuidPasswordContentDeliveryConfig
            {
                Enabled = config.GetBoolean("Enabled", false),
                PhpApiBaseUrl = new Uri(config.GetString("PhpApiBaseUrl", "https://localhost")),
                SharedSecret = config.GetString("SharedSecret", string.Empty),
                RequestTimeoutMs = config.GetInt("RequestTimeoutMs", 5000),
                MaxRetries = config.GetInt("MaxRetries", 2),
                ProxyBinary = config.GetBoolean("ProxyBinary", false),
                RateLimitBackoffMs = config.GetInt("RateLimitBackoffMs", 500),
                LoggingLevel = config.GetString("LoggingLevel", "INFO")
            };
        }
    }

#region Config
    /// <summary>
    /// Strongly typed request payload from viewers.
    /// </summary>
    internal sealed class FetchRequest
    {
        [JsonPropertyName("avatar_uuid")]
        public string AvatarUuid { get; set; } = string.Empty;

        [JsonPropertyName("password")]
        public string Password { get; set; } = string.Empty;

        [JsonPropertyName("request")]
        public string Request { get; set; } = string.Empty;

        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;
    }

#endregion

#region Error Handling
    internal static class RequestValidator
    {
        private static readonly Guid EmptyGuid = Guid.Empty;

        public static bool TryValidateFetch(FetchRequest payload, out string? error)
        {
            if (payload == null)
            {
                error = "invalid_payload";
                return false;
            }

            if (!UUID.TryParse(payload.AvatarUuid, out var uuid) || uuid == EmptyGuid)
            {
                error = "invalid_uuid";
                return false;
            }

            if (string.IsNullOrWhiteSpace(payload.Password) || payload.Password.Length < 8)
            {
                error = "invalid_password";
                return false;
            }

            if (string.IsNullOrWhiteSpace(payload.Request))
            {
                error = "invalid_request";
                return false;
            }

            if (string.IsNullOrWhiteSpace(payload.Id))
            {
                error = "invalid_id";
                return false;
            }

            error = null;
            return true;
        }
    }

#endregion

#region Init
    public sealed class UuidPasswordContentDeliveryModule : ISharedRegionModule
    {
        private static readonly ILog Log = LogManager.GetLogger("UuPwContentDelivery.Module");
        private readonly List<Scene> _scenes = new();
        private UuidPasswordContentDeliveryConfig? _config;
        private PhpApiClient? _phpClient;
        private IHttpServer? _httpServer;
        private bool _initialised;

        public string Name => "UuidPasswordContentDeliveryModule";

        public Type ReplaceableInterface => null!;

        public void Initialise(IConfigSource source)
        {
            _config = UuidPasswordContentDeliveryConfig.From(source);
            if (!_config.Enabled)
            {
                Log.Info("UuidPasswordContentDeliveryModule disabled via configuration.");
                return;
            }

            _phpClient = new PhpApiClient(_config);
            _initialised = true;
            Log.Info("UuidPasswordContentDeliveryModule initialised.");
        }

        public void PostInitialise()
        {
        }

        public void Close()
        {
            _phpClient?.Dispose();
            _phpClient = null;
            _initialised = false;
        }

        public void AddRegion(Scene scene)
        {
            if (!_initialised)
            {
                return;
            }

            if (scene == null) throw new ArgumentNullException(nameof(scene));
            _scenes.Add(scene);
            if (_httpServer == null)
            {
                _httpServer = scene.RequestModuleInterface<ISimulationBase>()?.GetHttpServer(0);
            }

            if (_httpServer == null)
            {
                Log.Error("Unable to acquire HTTP server for content delivery endpoint.");
                return;
            }

            _httpServer.AddStreamHandler(new RestStreamHandler("POST", "/content-delivery/fetch", FetchHandler, "UuidPasswordContentDeliveryFetch"));
            _httpServer.AddStreamHandler(new RestStreamHandler("POST", "/content-delivery/auth-check", HealthHandler, "UuidPasswordContentDeliveryAuth"));
            Log.InfoFormat("Content delivery endpoints registered on region {0}", scene.RegionInfo.RegionName);
        }

        public void RemoveRegion(Scene scene)
        {
            _scenes.Remove(scene);
        }

        public void RegionLoaded(Scene scene)
        {
        }

#endregion

#region HTTP Handlers
        private string HealthHandler(string path, Stream request, OSHttpRequest httpRequest, OSHttpResponse httpResponse)
        {
            if (!_initialised || _phpClient == null)
            {
                return Error(httpResponse, HttpStatusCode.ServiceUnavailable, "module_disabled", null);
            }

            httpResponse.StatusCode = (int)HttpStatusCode.OK;
            return JsonSerializer.Serialize(new { ok = true });
        }

        private string FetchHandler(string path, Stream requestStream, OSHttpRequest httpRequest, OSHttpResponse httpResponse)
        {
            var correlationId = EnsureCorrelationId(httpRequest, httpResponse);
            try
            {
                if (!_initialised || _phpClient == null)
                {
                    return Error(httpResponse, HttpStatusCode.ServiceUnavailable, "module_disabled", correlationId);
                }

                FetchRequest? payload;
                using (var reader = new StreamReader(requestStream, Encoding.UTF8, leaveOpen: true))
                {
                    var body = reader.ReadToEnd();
                    payload = JsonSerializer.Deserialize<FetchRequest>(body);
                }

                if (!RequestValidator.TryValidateFetch(payload!, out var error))
                {
                    Log.WarnFormat("[{0}] Invalid payload: {1}", correlationId, error);
                    return Error(httpResponse, HttpStatusCode.BadRequest, error ?? "invalid_payload", correlationId);
                }

                var cts = CancellationTokenSource.CreateLinkedTokenSource(httpRequest.TimedOutToken);
                cts.CancelAfter(TimeSpan.FromMilliseconds(_config!.RequestTimeoutMs));

                return FetchInternalAsync(payload!, httpResponse, correlationId, cts.Token).GetAwaiter().GetResult();
            }
            catch (JsonException ex)
            {
                Log.WarnFormat("[{0}] Failed to parse request: {1}", correlationId, ex.Message);
                return Error(httpResponse, HttpStatusCode.BadRequest, "invalid_json", correlationId);
            }
            catch (Exception ex)
            {
                Log.ErrorFormat("[{0}] Unhandled exception: {1}", correlationId, ex);
                return Error(httpResponse, HttpStatusCode.InternalServerError, "internal_error", correlationId);
            }
        }

        private async Task<string> FetchInternalAsync(FetchRequest payload, OSHttpResponse httpResponse, string correlationId, CancellationToken cancellationToken)
        {
            if (_phpClient == null)
            {
                return Error(httpResponse, HttpStatusCode.ServiceUnavailable, "module_disabled", correlationId);
            }

            var auth = await _phpClient.AuthenticateAsync(payload.AvatarUuid, payload.Password, cancellationToken, correlationId).ConfigureAwait(false);
            if (!auth.Ok || string.IsNullOrEmpty(auth.Token))
            {
                return Error(httpResponse, HttpStatusCode.Unauthorized, auth.ErrorCode ?? "auth_failed", correlationId, auth.Message);
            }

            var authz = await _phpClient.AuthorizeAsync(auth.Token, payload.Request, payload.Id, cancellationToken, correlationId).ConfigureAwait(false);
            if (!authz.Ok)
            {
                var status = authz.ErrorCode switch
                {
                    "not_found" => HttpStatusCode.NotFound,
                    "rate_limited" => (HttpStatusCode)429,
                    "not_authorized" => HttpStatusCode.Forbidden,
                    _ => HttpStatusCode.BadRequest
                };

                return Error(httpResponse, status, authz.ErrorCode ?? "authorization_failed", correlationId, authz.Message);
            }

            if (!string.IsNullOrEmpty(authz.Url))
            {
                if (_config!.ProxyBinary)
                {
                    return await ProxyBinaryAsync(authz.Url, httpResponse, correlationId, cancellationToken).ConfigureAwait(false);
                }

                httpResponse.StatusCode = (int)HttpStatusCode.Found;
                httpResponse.RedirectLocation = authz.Url;
                httpResponse.ContentType = "application/json";
                return JsonSerializer.Serialize(new
                {
                    ok = true,
                    url = authz.Url,
                    metadata = authz.Metadata,
                    correlation_id = correlationId
                });
            }

            if (authz.Binary != null)
            {
                httpResponse.StatusCode = (int)HttpStatusCode.OK;
                httpResponse.ContentType = authz.ContentType ?? "application/octet-stream";
                httpResponse.RawBuffer = authz.Binary;
                return string.Empty;
            }

            return Error(httpResponse, HttpStatusCode.BadGateway, "invalid_response", correlationId);
        }

        private async Task<string> ProxyBinaryAsync(string url, OSHttpResponse httpResponse, string correlationId, CancellationToken cancellationToken)
        {
            if (_phpClient == null)
            {
                return Error(httpResponse, HttpStatusCode.ServiceUnavailable, "module_disabled", correlationId);
            }

            try
            {
                using var response = await _phpClient.DownloadAsync(url, cancellationToken).ConfigureAwait(false);
                var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
                httpResponse.StatusCode = (int)response.StatusCode;
                httpResponse.ContentType = response.Content.Headers.ContentType?.ToString() ?? "application/octet-stream";
                httpResponse.RawBuffer = bytes;
                return string.Empty;
            }
            catch (Exception ex)
            {
                Log.ErrorFormat("[{0}] Proxy download failed: {1}", correlationId, ex.Message);
                return Error(httpResponse, HttpStatusCode.BadGateway, "proxy_failed", correlationId);
            }
        }

#endregion

#region Error Handling
        private static string Error(OSHttpResponse response, HttpStatusCode status, string code, string? correlationId, string? message = null)
        {
            response.StatusCode = (int)status;
            response.ContentType = "application/json";
            var payload = new
            {
                ok = false,
                error_code = code,
                message = message ?? status.ToString(),
                correlation_id = correlationId
            };
            return JsonSerializer.Serialize(payload);
        }

#endregion

#region Logging
        private static string EnsureCorrelationId(OSHttpRequest request, OSHttpResponse response)
        {
            var id = request.Headers["X-Correlation-Id"];
            if (string.IsNullOrWhiteSpace(id))
            {
                id = Guid.NewGuid().ToString();
            }

            response.AddHeader("X-Correlation-Id", id);
            return id;
        }
    }

#endregion
}
