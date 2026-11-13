//! Portable parts of the Counter-Strike 1.6 companion: its command line, the gateway's
//! published keys, the game's command line and the session file the telemetry bridge reads.

use std::path::{Path, PathBuf};

use carthago_crypto::VerifyingKey;

pub const USAGE: &str = "\
usage: carthago-cs16 --keys public-keys.json (--game-dir DIR | --exe PATH | --attach PID)
                     [--gateway wss://127.0.0.1:8750/v1/client] [--tenant demo] [--build cs16]
                     [--player ID] [--session-file FILE] [--log FILE] [--no-tpm]
                     [--input-monitor] [--max-secs N] [--no-alert] [--alert-secs N]
                     [--end-match-on-detect] [-- game arguments]
       carthago-cs16 --test-alert [--player ID] [--alert-secs N] [--end-match-on-detect]

Opens an attested session with the gateway, then starts the game (default arguments:
-game cstrike) and watches it from outside with read-only access until it exits.
--game-dir starts hl.exe in DIR or, in a build that has none, cstrike.exe; --exe names the
program. --attach watches a game that is already running instead of starting one.

When the gateway reports that the session was flagged, a full-screen alert is shown in a
window of this program (--no-alert: only a log line). It closes on Esc, a click, or after
--alert-secs seconds (default 20, 0 = stays until closed). The game is left running unless
--end-match-on-detect is given: then the game this program started is asked to close.
--test-alert shows the alert at once, without a gateway or a game, and exits.";

/// The game program in a GoldSrc folder: `hl.exe`, or `cstrike.exe` in builds that ship the
/// same program under that name and no `hl.exe`. Nothing else in the folder is ever chosen.
pub fn engine_exe(dir: &Path) -> PathBuf {
    ["hl.exe", "cstrike.exe"].iter().map(|n| dir.join(n)).find(|p| p.is_file()).unwrap_or_else(|| dir.join("hl.exe"))
}

/// Modules that mark a process as the running game: the engine DLL (hardware or software
/// renderer) and the engine's file system module, which every GoldSrc client loads first
/// and which stays in the loader's list in old builds that map the engine DLL themselves.
pub const ENGINE_MODULES: [&str; 3] = ["hw.dll", "sw.dll", "filesystem_stdio.dll"];

/// Programs found in a game folder that are never the game: the crash reporter, the TV
/// proxy, dedicated servers and installers. Some of them load engine modules too.
pub fn never_the_game(exe_name: &str) -> bool {
    let n = exe_name.to_lowercase();
    let stem = n.strip_suffix(".exe").unwrap_or(&n);
    matches!(stem, "crashpad_handler" | "hltv" | "hlds" | "hlds_run")
        || ["unins", "uninst", "setup", "install", "carthago"].iter().any(|p| stem.starts_with(p))
}

/// How the companion ends. The values are its process exit codes.
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 1;
    pub const NO_SESSION: i32 = 2;
    pub const NOT_STARTED: i32 = 3;
    pub const SESSION_LOST: i32 = 4;
    /// The started program ended within seconds and no game process was found.
    pub const GAME_NEVER_RAN: i32 = 5;
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
    /// Show the alert screen when the gateway flags the session.
    pub alert: bool,
    /// Seconds the alert stays up by itself; 0 keeps it until it is closed.
    pub alert_secs: u32,
    /// Also close the game this companion started when the session is flagged.
    pub end_match_on_detect: bool,
    /// Show the alert screen now, as a preview, and exit.
    pub test_alert: bool,
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
        alert: true,
        alert_secs: 20,
        end_match_on_detect: false,
        test_alert: false,
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
            "--no-alert" => o.alert = false,
            "--alert-secs" => o.alert_secs = val()?.parse().ok().filter(|s| *s <= 600).ok_or("--alert-secs: 0 to 600")?,
            "--end-match-on-detect" => o.end_match_on_detect = true,
            "--test-alert" => o.test_alert = true,
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if o.player.is_empty() || o.player.len() > 128 {
        return Err("--player must be 1 to 128 characters".into());
    }
    if o.test_alert {
        if exe.is_some() || attach.is_some() {
            return Err("--test-alert shows the alert only; it takes no game".into());
        }
        return Ok(o);
    }
    if o.keys.as_os_str().is_empty() {
        return Err("--keys is required".into());
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

/// What the alert screen says. The companion draws it; the words are decided here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertText {
    /// Set on a preview or a test notice: nothing was detected.
    pub tag: Option<String>,
    pub brand: String,
    pub title: String,
    pub subtitle: String,
    pub reason: String,
    /// Label and value pairs under the reason: player, session, time.
    pub details: Vec<(String, String)>,
    pub footer: String,
}

/// `reason` is the notice's one-line category text; it never names a rule. `session_id` is
/// empty for a preview shown without a session.
pub fn alert_text(reason: &str, test: bool, player: &str, session_id: &str, issued_at_ms: u64, closes_game: bool) -> AlertText {
    let mut details = vec![("PLAYER".to_owned(), player.to_owned())];
    details.push(("SESSION".to_owned(), if session_id.is_empty() { "none (preview)".to_owned() } else { session_id.to_owned() }));
    details.push(("TIME".to_owned(), utc_time(issued_at_ms)));
    AlertText {
        tag: test.then(|| "TEST ALERT - NOTHING WAS DETECTED".to_owned()),
        brand: "CARTHAGO WATCHDOG".into(),
        title: "CHEATER DETECTED".into(),
        subtitle: if closes_game { "MATCH TERMINATED" } else { "THIS MATCH HAS BEEN FLAGGED" }.into(),
        reason: reason.to_owned(),
        details,
        footer: "Press Esc or click to close. This screen is a window of the Carthago Watchdog companion; nothing in the game was changed.".into(),
    }
}

/// "2026-11-13 14:02:11 UTC" for Unix milliseconds.
pub fn utc_time(ms: u64) -> String {
    let secs = ms / 1000;
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil date from days since 1970-01-01 (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
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
    fn helper_programs_are_never_the_game() {
        for n in ["crashpad_handler.exe", "HLTV.exe", "hlds.exe", "unins000.exe", "Uninstall.exe", "setup.exe", "carthago-cs16.exe"] {
            assert!(never_the_game(n), "{n}");
        }
        for n in ["hl.exe", "cstrike.exe", "CStrike.exe", "launcher.exe", "play.exe"] {
            assert!(!never_the_game(n), "{n}");
        }
    }

    #[test]
    fn alert_options_default_to_alert_only() {
        let o = parse_args(&args(&["--keys", "k.json", "--exe", "cstrike.exe"])).unwrap();
        assert!(o.alert && !o.end_match_on_detect && !o.test_alert);
        assert_eq!(o.alert_secs, 20);
        let o = parse_args(&args(&["--keys", "k.json", "--exe", "cstrike.exe", "--end-match-on-detect", "--alert-secs", "0"])).unwrap();
        assert!(o.alert && o.end_match_on_detect);
        assert_eq!(o.alert_secs, 0);
        assert!(!parse_args(&args(&["--keys", "k.json", "--exe", "cstrike.exe", "--no-alert"])).unwrap().alert);
        assert!(parse_args(&args(&["--keys", "k.json", "--exe", "cstrike.exe", "--alert-secs", "soon"])).is_err());

        // A preview needs neither the gateway's keys nor a game, and takes no game.
        let o = parse_args(&args(&["--test-alert", "--player", "ala"])).unwrap();
        assert!(o.test_alert && o.player == "ala");
        assert!(parse_args(&args(&["--test-alert", "--exe", "cstrike.exe"])).is_err());
    }

    #[test]
    fn alert_says_what_happened_and_never_more() {
        let t = alert_text("Aim assistance was detected in this match.", false, "cs16-local-player", "00112233445566778899aabbccddeeff", 1_794_225_800_000, false);
        assert_eq!((t.brand.as_str(), t.title.as_str(), t.subtitle.as_str()), ("CARTHAGO WATCHDOG", "CHEATER DETECTED", "THIS MATCH HAS BEEN FLAGGED"));
        assert_eq!(t.tag, None);
        assert_eq!(t.reason, "Aim assistance was detected in this match.");
        assert_eq!(
            t.details,
            vec![
                ("PLAYER".to_owned(), "cs16-local-player".to_owned()),
                ("SESSION".to_owned(), "00112233445566778899aabbccddeeff".to_owned()),
                ("TIME".to_owned(), "2026-11-09 12:03:20 UTC".to_owned()),
            ]
        );
        let t = alert_text("x", false, "p", "s", 0, true);
        assert_eq!(t.subtitle, "MATCH TERMINATED");

        // A test is labelled as one on the screen itself.
        let t = alert_text("Test of the alert screen. Nothing was detected.", true, "p", "", 0, false);
        assert_eq!(t.tag.as_deref(), Some("TEST ALERT - NOTHING WAS DETECTED"));
        assert_eq!(t.details[1].1, "none (preview)");
    }

    #[test]
    fn formats_utc_time() {
        assert_eq!(utc_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc_time(951_782_400_000), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc_time(1_794_225_800_000), "2026-11-09 12:03:20 UTC");
        assert_eq!(utc_time(4_102_444_799_999), "2099-12-31 23:59:59 UTC");
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
