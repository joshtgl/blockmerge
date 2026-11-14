{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.blockmerge;
  settingsFormat = pkgs.formats.toml { };
  configFile =
    if cfg.configFile != null then
      cfg.configFile
    else
      settingsFormat.generate "blockmerge.toml" cfg.settings;
in
{
  options.services.blockmerge = {
    enable = lib.mkEnableOption "the blockmerge scheduled blocklist generator";

    package = lib.mkPackageOption pkgs "blockmerge" { };

    settings = lib.mkOption {
      inherit (settingsFormat) type;
      default = { };
      description = ''
        Contents of `blockmerge.toml`. A `[schedule]` section is required for daemon mode.
        Keep API keys out of this attrset; reference them with `api_key_env` and
        provide them through {option}`services.blockmerge.environmentFile`.
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Existing `blockmerge.toml` to use instead of {option}`services.blockmerge.settings`.";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Environment file with secrets such as `IPLOCATE_API_KEY`.";
    };

    outputDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/blockmerge/output";
      description = "Directory receiving `inbound.txt` and `outbound.txt`. Readable by the `blockmerge` group.";
    };
  };

  config = lib.mkIf cfg.enable {
    users.groups.blockmerge = { };
    users.users.blockmerge = {
      isSystemUser = true;
      group = "blockmerge";
    };

    systemd.tmpfiles.settings."10-blockmerge".${cfg.outputDir}.d = {
      user = "blockmerge";
      group = "blockmerge";
      mode = "0755";
    };

    systemd.services.blockmerge = {
      description = "Blockmerge IP blocklist generator";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      restartTriggers = [ configFile ];

      environment = {
        BLOCKMERGE_CONFIG_FILE = toString configFile;
        BLOCKMERGE_STATE_FILE = "/var/lib/blockmerge/state.json";
        BLOCKMERGE_CACHE_DIR = "/var/cache/blockmerge";
        BLOCKMERGE_INBOUND_OUTPUT = "${cfg.outputDir}/inbound.txt";
        BLOCKMERGE_OUTBOUND_OUTPUT = "${cfg.outputDir}/outbound.txt";
      };

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} --daemon";
        EnvironmentFile = lib.optional (cfg.environmentFile != null) cfg.environmentFile;
        User = "blockmerge";
        Group = "blockmerge";
        StateDirectory = "blockmerge";
        CacheDirectory = "blockmerge";
        ReadWritePaths = [ cfg.outputDir ];
        Restart = "always";
        RestartSec = "10s";
        MemoryMax = "512M";

        CapabilityBoundingSet = "";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = true;
        ProtectHostname = true;
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectProc = "invisible";
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        UMask = "0022";
      };
    };
  };
}
