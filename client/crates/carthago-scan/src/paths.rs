//! Classifies module paths so only modules outside the Windows directory are reported.

use carthago_proto::v1::ModulePathClass;

#[derive(Debug, Clone, Default)]
pub struct Dirs {
    /// Lowercase, backslash-terminated prefixes.
    pub windows: String,
    pub game: String,
    pub program_files: Vec<String>,
}

fn norm_dir(s: &str) -> String {
    let mut d = s.replace('/', "\\").to_lowercase();
    if !d.is_empty() && !d.ends_with('\\') {
        d.push('\\');
    }
    d
}

impl Dirs {
    pub fn new(windows: &str, game_exe: &str, program_files: &[&str]) -> Self {
        let game = game_exe.rfind(['\\', '/']).map_or("", |i| &game_exe[..i]);
        Self {
            windows: norm_dir(windows),
            game: norm_dir(game),
            program_files: program_files.iter().filter(|p| !p.is_empty()).map(|p| norm_dir(p)).collect(),
        }
    }

    /// `None` for modules under the Windows directory (not reported).
    pub fn classify(&self, path: &str) -> Option<ModulePathClass> {
        let p = path.strip_prefix(r"\\?\").unwrap_or(path).replace('/', "\\").to_lowercase();
        if !self.windows.is_empty() && p.starts_with(&self.windows) {
            return None;
        }
        if !self.game.is_empty() && p.starts_with(&self.game) {
            return Some(ModulePathClass::GameDir);
        }
        if self.program_files.iter().any(|d| p.starts_with(d.as_str())) {
            return Some(ModulePathClass::ProgramFiles);
        }
        Some(ModulePathClass::Other)
    }
}

pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths() {
        let d = Dirs::new(r"C:\Windows", r"D:\Games\Arena\Arena.exe", &[r"C:\Program Files", r"C:\Program Files (x86)", ""]);
        assert_eq!(d.classify(r"C:\WINDOWS\System32\ntdll.dll"), None);
        assert_eq!(d.classify(r"\\?\C:\Windows\SysWOW64\x.dll"), None);
        assert_eq!(d.classify(r"D:\Games\Arena\bin\engine.dll"), Some(ModulePathClass::GameDir));
        assert_eq!(d.classify(r"C:\Program Files (x86)\Steam\gameoverlayrenderer64.dll"), Some(ModulePathClass::ProgramFiles));
        assert_eq!(d.classify(r"C:\Users\p\AppData\Local\Temp\x.dll"), Some(ModulePathClass::Other));
        // a sibling directory sharing a prefix is not the game directory
        assert_eq!(d.classify(r"D:\Games\ArenaCheats\x.dll"), Some(ModulePathClass::Other));
    }

    #[test]
    fn base_names() {
        assert_eq!(base_name(r"C:\a\b\cheat.dll"), "cheat.dll");
        assert_eq!(base_name("plain.dll"), "plain.dll");
    }
}
