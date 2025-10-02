// SPDX-License-Identifier: MIT
#nullable enable
using System;
using System.Collections.Generic;
using System.Threading;

namespace OpenMetaverse
{
    public readonly struct UUID : IEquatable<UUID>
    {
        private readonly Guid _value;

        private UUID(Guid value)
        {
            _value = value;
        }

        public static bool TryParse(string? input, out UUID uuid)
        {
            if (Guid.TryParse(input, out var guid))
            {
                uuid = new UUID(guid);
                return true;
            }

            uuid = default;
            return false;
        }

        public bool Equals(UUID other) => _value.Equals(other._value);
        public override bool Equals(object? obj) => obj is UUID other && Equals(other);
        public override int GetHashCode() => _value.GetHashCode();
        public static bool operator ==(UUID left, UUID right) => left.Equals(right);
        public static bool operator !=(UUID left, UUID right) => !left.Equals(right);
        public static implicit operator Guid(UUID uuid) => uuid._value;
    }
}

namespace OpenSim.Framework
{
    public interface IConfig
    {
        bool GetBoolean(string key, bool defaultValue);
        string GetString(string key, string defaultValue);
        int GetInt(string key, int defaultValue);
    }

    public interface IConfigCollection
    {
        IConfig? this[string section] { get; }
    }

    public interface IConfigSource
    {
        IConfigCollection Configs { get; }
    }

    public sealed class OSHttpRequest
    {
        public Dictionary<string, string> Headers { get; } = new();
        public CancellationToken TimedOutToken { get; set; } = CancellationToken.None;
    }

    public sealed class OSHttpResponse
    {
        public int StatusCode { get; set; }
        public string ContentType { get; set; } = "application/json";
        public string? RedirectLocation { get; set; }
        public byte[]? RawBuffer { get; set; }

        private readonly Dictionary<string, string> _headers = new();

        public void AddHeader(string key, string value) => _headers[key] = value;
    }
}

namespace OpenSim.Framework.Servers.HttpServer
{
    public interface IHttpServer
    {
        void AddStreamHandler(RestStreamHandler handler);
    }

    public sealed class RestStreamHandler
    {
        public RestStreamHandler(string method, string path, Func<string, System.IO.Stream, OpenSim.Framework.OSHttpRequest, OpenSim.Framework.OSHttpResponse, string> handler, string name)
        {
        }
    }
}

namespace OpenSim.Region.Framework.Interfaces
{
    public interface ISimulationBase
    {
        OpenSim.Framework.Servers.HttpServer.IHttpServer? GetHttpServer(uint port);
    }

    public interface ISharedRegionModule
    {
        string Name { get; }
        Type ReplaceableInterface { get; }
        void Initialise(OpenSim.Framework.IConfigSource source);
        void PostInitialise();
        void Close();
        void AddRegion(OpenSim.Region.Framework.Scenes.Scene scene);
        void RemoveRegion(OpenSim.Region.Framework.Scenes.Scene scene);
        void RegionLoaded(OpenSim.Region.Framework.Scenes.Scene scene);
    }
}

namespace OpenSim.Region.Framework.Scenes
{
    public sealed class RegionInfo
    {
        public string RegionName { get; set; } = string.Empty;
    }

    public sealed class Scene
    {
        public RegionInfo RegionInfo { get; } = new();

        public T? RequestModuleInterface<T>() where T : class
        {
            return null;
        }
    }
}
