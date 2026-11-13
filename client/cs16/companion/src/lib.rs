//! Portable parts of the Counter-Strike 1.6 companion: its command line, the gateway's
//! published keys, the game's command line and the session file the telemetry bridge reads.

use std::path::{Path, PathBuf};

use carthago_crypto::VerifyingKey;

pub const USAGE: &str = "\
usage: carthago-cs16 --keys public-keys.json (--game-dir DIR | --exe PATH | --attach PID)
                     [--gateway wss://127.0.0.1:8750/v1/client] [--tenant demo] [--build cs16]
                     [--player ID] [--session-file FILE] [--log FILE] [--no-tpm]
                     [--input-monitor] [--max-secs N] [-- game arguments]

Opens an attested session with the gateway, then starts the game (default arguments:
-game cstrike) and watches it from outside with read-only access until it exits.
--game-dir starts hl.exe in DIR or, in a build that has none, cstrike.exe; --exe names the
program. --attach watches a game that is already running instead of starting one.";

/// The game program in a GoldSrc folder: `hl.exe`, or `cstrike.exe` in builds that ship the
/// same program under that name and no `hl.exe`. Nothing else in the folder is ever chosen.
pub fn engine_exe(dir: &Path) -> PathBuf {
    ["hl.exe", "cstrike.exe"].iter().map(|n| dir.join(n)).find(|p| p.is_file()).unwrap_or_else(|| dir.join("hl.exe"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Game {
    Launch { exe: PathBuf, args: Vec<String> },
    Attach(u32),
}

#[derive(Debug, Clone)]
pub struct Options {
    pub keys: PathBuf,
    pub game: Game,
    pub gateway: String,
    pub tenant: String,
    pub build: String,
    pub player: String,
    pub session_file: Option<PathBuf>,
    pub log: Option<PathBuf>,
    pub allow_tpm: bool,
    pub input_monitor: bool,
    pub max_secs: Option<u64>,
}

pub fn parse_args(argv: &[String]) -> Result<Options, String> {
    let (own, game_args) = match argv.iter().position(|a| a == "--") {
        Some(i) => (&argv[..i], argv[i + 1..].to_vec()),
        None => (argv, Vec::new()),
    };
    let mut o = Options {
        keys: PathBuf::new(),
        game: Game::Attach(0),
        gateway: "wss://127.0.0.1:8750/v1/client".into(),
        tenant: "demo".into(),
        build: "cs16".into(),
        player: "cs16-local-player".into(),
        session_file: None,
        log: None,
        allow_tpm: true,
        input_monitor: false,
        max_secs: None,
    };
    let (mut exe, mut attach) = (None, None);
    let mut it = own.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--keys" => o.keys = val()?.into(),
            "--game-dir" => exe = Some(engine_exe(Path::new(&val()?))),
            "--exe" => exe = Some(PathBuf::from(val()?)),
            "--attach" => attach = Some(val()?.parse::<u32>().map_err(|_| "--attach: not a process id")?),
            "--gateway" => o.gateway = val()?,
            "--tenant" => o.tenant = val()?,
            "--build" => o.build = val()?,
            "--player" => o.player = val()?,
            "--session-file" => o.session_file = Some(val()?.into()),
            "--log" => o.log = Some(val()?.into()),
            "--max-secs" => o.max_secs = Some(val()?.parse().map_err(|_| "--max-secs: not a number")?),
            "--no-tpm" => o.allow_tpm = false,
            "--input-monitor" => o.input_monitor = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if o.keys.as_os_str().is_empty() {
        return Err("--keys is required".into());
    }
    if o.player.is_empty() || o.player.len() > 128 {
        return Err("--player must be 1 to 128 characters".into());
    }
    o.game = match (exe, attach) {
        (Some(exe), None) => Game::Launch { exe, args: if game_args.is_empty() { vec!["-game".into(), "cstrike".into()] } else { game_args } },
        (None, Some(pid)) if pid != 0 => Game::Attach(pid),
        _ => return Err("give exactly one of --game-dir, --exe or --attach".into()),
    };
    Ok(o)
}

/// What the companion pins from the gateway's `public-keys.json`.
pub struct GatewayKeys {
    pub server_identity: VerifyingKey,
    pub tls_pins: Vec<carthago_net::Pin>,
}

pub fn parse_keys(json: &str) -> Result<GatewayKeys, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("public keys json: {e}"))?;
    let key_hex = v["server_identity"]["public_key"].as_str().ok_or("public keys json: no server_identity.public_key")?;
    let server_identity = hex::decode(key_hex.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or("public keys json: server identity is not an Ed25519 key")?;
    let pins: Vec<&str> = match &v["tls_spki_sha256"] {
        serde_json::Value::Array(a) => a.iter().filter_map(|p| p.as_str()).collect(),
        serde_json::Value::String(s) => vec![s.as_str()],
        _ => Vec::new(),
    };
    let tls_pins = carthago_net::parse_pins(&pins.join(","))?;
    Ok(GatewayKeys { server_identity, tls_pins })
}

/// Quotes one argument the way the Microsoft C runtime parses a command line.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }
    let mut out = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                backslashes = 0;
                out.push('"');
                continue;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
            }
        }
        if c != '\\' {
            out.push(c);
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

pub fn command_line(exe: &Path, args: &[String]) -> String {
    std::iter::once(quote_arg(&exe.to_string_lossy())).chain(args.iter().map(|a| quote_arg(a))).collect::<Vec<_>>().join(" ")
}

/// What the telemetry bridge needs to bind the local player's match slot to this session.
/// The bridge verifies the token against the gateway's keys itself; nothing here is trusted
/// on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionFile {
    pub session_id: String,
    pub token: String,
    pub player_hash: String,
    pub trust_level: u32,
    pub attest_flags: u64,
    pub game_pid: u32,
    /// "active" while the session is up; "ended" once the game or the session is gone.
    pub state: String,
}

impl SessionFile {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "session_id": self.session_id,
            "token": self.token,
            "player_hash": self.player_hash,
            "trust_level": self.trust_level,
            "attest_flags": self.attest_flags,
            "game_pid": self.game_pid,
            "state": self.state,
        })
        .to_string()
    }

    pub fn parse(json: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("session file: {e}"))?;
        let s = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
        Ok(Self {
            session_id: s("session_id"),
            token: s("token"),
            player_hash: s("player_hash"),
            trust_level: v["trust_level"].as_u64().unwrap_or(0) as u32,
            attest_flags: v["attest_flags"].as_u64().unwrap_or(0),
            game_pid: v["game_pid"].as_u64().unwrap_or(0) as u32,
            state: s("state"),
        })
    }

    /// Replaces the file in one step, so a reader never sees half of it.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.to_json())?;
        std::fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_launch_with_default_and_explicit_game_arguments() {
        let o = parse_args(&args(&["--keys", "k.json", "--game-dir", "E:/Games/CS"])).unwrap();
        assert_eq!(o.game, Game::Launch { exe: PathBuf::from("E:/Games/CS").join("hl.exe"), args: args(&["-game", "cstrike"]) });
        assert!(o.allow_tpm && !o.input_monitor);
        let o = parse_args(&args(&["--keys", "k.json", "--exe", "hl.exe", "--no-tpm", "--", "-game", "cstrike", "+map", "de_dust2"])).unwrap();
        assert_eq!(o.game, Game::Launch { exe: "hl.exe".into(), args: args(&["-game", "cstrike", "+map", "de_dust2"]) });
        assert!(!o.allow_tpm);
    }

    #[test]
    fn game_dir_picks_hl_then_cstrike_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("carthago-cs16-exe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for other in ["crashpad_handler.exe", "hltv.exe", "unins000.exe"] {
            std::fs::write(dir.join(other), b"x").unwrap();
        }
        assert_eq!(engine_exe(&dir), dir.join("hl.exe"));
        std::fs::write(dir.join("cstrike.exe"), b"x").unwrap();
        assert_eq!(engine_exe(&dir), dir.join("cstrike.exe"));
        let o = parse_args(&args(&["--keys", "k.json", "--game-dir", dir.to_str().unwrap()])).unwrap();
        assert_eq!(o.game, Game::Launch { exe: dir.join("cstrike.exe"), args: args(&["-game", "cstrike"]) });
        std::fs::write(dir.join("hl.exe"), b"x").unwrap();
        assert_eq!(engine_exe(&dir), dir.join("hl.exe"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_ambiguous_or_missing_targets() {
        assert!(parse_args(&args(&["--keys", "k.json"])).is_err());
        assert!(parse_args(&args(&["--keys", "k.json", "--exe", "hl.exe", "--attach", "4"])).is_err());
        assert!(parse_args(&args(&["--game-dir", "x"])).is_err());
        assert_eq!(parse_args(&args(&["--keys", "k.json", "--attach", "1234"])).unwrap().game, Game::Attach(1234));
    }

    #[test]
    fn quotes_like_the_c_runtime_expects() {
        assert_eq!(quote_arg("-game"), "-game");
        assert_eq!(quote_arg(r"E:\My Games\hl.exe"), r#""E:\My Games\hl.exe""#);
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_arg(""), r#""""#);
        assert_eq!(command_line(Path::new(r"E:\CS 1.6\hl.exe"), &args(&["-game", "cstrike"])), r#""E:\CS 1.6\hl.exe" -game cstrike"#);
    }

    #[test]
    fn reads_gateway_keys_with_and_without_tls_pins() {
        let key = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
        let pin = "aa".repeat(32);
        let k = parse_keys(&format!(r#"{{"server_identity":{{"kid":"x","public_key":"{key}"}},"tls_spki_sha256":["{pin}"]}}"#)).unwrap();
        assert_eq!(k.tls_pins, vec![[0xaa; 32]]);
        let k = parse_keys(&format!(r#"{{"server_identity":{{"kid":"x","public_key":"{key}"}}}}"#)).unwrap();
        assert!(k.tls_pins.is_empty());
        assert!(parse_keys(r#"{"server_identity":{"public_key":"zz"}}"#).is_err());
    }

    #[test]
    fn session_file_round_trips() {
        let s = SessionFile {
            session_id: "00112233445566778899aabbccddeeff".into(),
            token: "v4.public.abc".into(),
            player_hash: "cs16-local-player".into(),
            trust_level: 3,
            attest_flags: 0x1f,
            game_pid: 4242,
            state: "active".into(),
        };
        assert_eq!(SessionFile::parse(&s.to_json()).unwrap(), s);
        let dir = std::env::temp_dir().join(format!("carthago-cs16-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("session.json");
        s.write(&p).unwrap();
        s.write(&p).unwrap();
        assert_eq!(SessionFile::parse(&std::fs::read_to_string(&p).unwrap()).unwrap(), s);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
