// SPDX-License-Identifier: MIT
#nullable enable
using System;

namespace OpenSim.Modules.ContentDelivery
{
    internal sealed class UuidPasswordContentDeliveryConfig
    {
        public bool Enabled { get; init; }
        public Uri PhpApiBaseUrl { get; init; } = new("https://localhost");
        public string SharedSecret { get; init; } = string.Empty;
        public int RequestTimeoutMs { get; init; } = 5000;
        public int MaxRetries { get; init; } = 2;
        public bool ProxyBinary { get; init; }
        public int RateLimitBackoffMs { get; init; } = 500;
        public string LoggingLevel { get; init; } = "INFO";
    }
}
