/* customizable color theme engine and syntax-highlighting palettes for ratatui */

use ratatui::style::Color;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/* active color palette configuring visual elements across all ratatui views */
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Palette {
    /* window surfaces and structural borders */
    pub background: (u8, u8, u8),
    pub foreground: (u8, u8, u8),
    pub border: (u8, u8, u8),
    pub border_active: (u8, u8, u8),
    pub status_bg: (u8, u8, u8),
    pub status_fg: (u8, u8, u8),
    pub cursor_bg: (u8, u8, u8),
    pub cursor_fg: (u8, u8, u8),
    pub selection_bg: (u8, u8, u8),

    /* disassembly syntax tokens */
    pub mnemonic: (u8, u8, u8),
    pub mnemonic_call: (u8, u8, u8),
    pub mnemonic_jump: (u8, u8, u8),
    pub mnemonic_ret: (u8, u8, u8),
    pub register: (u8, u8, u8),
    pub immediate: (u8, u8, u8),
    pub memory_bracket: (u8, u8, u8),
    pub branch_target: (u8, u8, u8),
    pub source_line: (u8, u8, u8),
    pub keyword: (u8, u8, u8),

    /* hex and ASCII inspection tokens */
    pub hex_offset: (u8, u8, u8),
    pub hex_zero: (u8, u8, u8),
    pub hex_printable: (u8, u8, u8),
    pub hex_nonprintable: (u8, u8, u8),
    pub hex_modified: (u8, u8, u8),

    /* control-flow graph and call-graph elements */
    pub node_border: (u8, u8, u8),
    pub node_header: (u8, u8, u8),
    pub edge_taken: (u8, u8, u8),
    pub edge_fallthrough: (u8, u8, u8),
    pub edge_unconditional: (u8, u8, u8),

    /* Shannon entropy gradient */
    pub entropy_low: (u8, u8, u8),
    pub entropy_mid: (u8, u8, u8),
    pub entropy_high: (u8, u8, u8),

    /* modal overlays and dialogs */
    pub modal_bg: (u8, u8, u8),
    pub modal_border: (u8, u8, u8),
    pub modal_selected: (u8, u8, u8),
}

/* convert RGB triplet tuple to ratatui Color */
#[inline]
pub fn to_color(rgb: (u8, u8, u8)) -> Color {
    Color::Rgb(rgb.0, rgb.1, rgb.2)
}

/* available built-in color theme presets */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemePreset {
    Nord,
    Dracula,
    Monokai,
    Gruvbox,
    Solarized,
    Custom,
}

impl ThemePreset {
    pub fn name(&self) -> &'static str {
        match self {
            ThemePreset::Nord => "Nord",
            ThemePreset::Dracula => "Dracula",
            ThemePreset::Monokai => "Monokai",
            ThemePreset::Gruvbox => "Gruvbox",
            ThemePreset::Solarized => "Solarized",
            ThemePreset::Custom => "Custom",
        }
    }
}

/* active theme configuration container */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Theme {
    pub preset: ThemePreset,
    pub palette: Palette,
}

impl Theme {
    /* construct Nord color scheme preset based on arctic cold palette */
    pub fn nord() -> Self {
        Self {
            preset: ThemePreset::Nord,
            palette: Palette {
                background: (46, 52, 64),       /* Nord0: #2E3440 */
                foreground: (236, 239, 244),   /* Nord6: #ECEFF4 */
                border: (76, 86, 106),          /* Nord3: #4C566A */
                border_active: (136, 192, 208), /* Nord8: #88C0D0 */
                status_bg: (59, 66, 82),        /* Nord1: #3B4252 */
                status_fg: (236, 239, 244),   /* Nord6: #ECEFF4 */
                cursor_bg: (129, 161, 193),     /* Nord9: #81A1C1 */
                cursor_fg: (46, 52, 64),        /* Nord0: #2E3440 */
                selection_bg: (67, 76, 94),     /* Nord2: #434C5E */

                mnemonic: (129, 161, 193),       /* Nord9: #81A1C1 */
                mnemonic_call: (136, 192, 208),  /* Nord8: #88C0D0 */
                mnemonic_jump: (180, 142, 173),  /* Nord15: #B48EAD */
                mnemonic_ret: (191, 97, 106),    /* Nord11: #BF616A */
                register: (235, 203, 139),      /* Nord13: #EBCB8B */
                immediate: (163, 190, 140),     /* Nord14: #A3BE8C */
                memory_bracket: (94, 129, 172), /* Nord10: #5E81AC */
                branch_target: (143, 188, 187), /* Nord7: #8FBCBB */
                source_line: (208, 135, 112),   /* Nord12: #D08770 */
                keyword: (129, 161, 193),       /* Nord9: #81A1C1 */

                hex_offset: (94, 129, 172),     /* Nord10: #5E81AC */
                hex_zero: (76, 86, 106),        /* Nord3: #4C566A */
                hex_printable: (236, 239, 244), /* Nord6: #ECEFF4 */
                hex_nonprintable: (94, 129, 172),/* Nord10: #5E81AC */
                hex_modified: (235, 203, 139),  /* Nord13: #EBCB8B */

                node_border: (136, 192, 208),   /* Nord8: #88C0D0 */
                node_header: (59, 66, 82),      /* Nord1: #3B4252 */
                edge_taken: (163, 190, 140),    /* Nord14: #A3BE8C */
                edge_fallthrough: (191, 97, 106),/* Nord11: #BF616A */
                edge_unconditional: (136, 192, 208),/* Nord8: #88C0D0 */

                entropy_low: (163, 190, 140),   /* Nord14: #A3BE8C */
                entropy_mid: (235, 203, 139),   /* Nord13: #EBCB8B */
                entropy_high: (191, 97, 106),   /* Nord11: #BF616A */

                modal_bg: (46, 52, 64),         /* Nord0: #2E3440 */
                modal_border: (136, 192, 208),  /* Nord8: #88C0D0 */
                modal_selected: (67, 76, 94),   /* Nord2: #434C5E */
            },
        }
    }

    /* construct Dracula color scheme preset featuring high-contrast dark accents */
    pub fn dracula() -> Self {
        Self {
            preset: ThemePreset::Dracula,
            palette: Palette {
                background: (40, 42, 54),       /* Background: #282A36 */
                foreground: (248, 248, 242),   /* Foreground: #F8F8F2 */
                border: (98, 114, 164),         /* Comment: #6272A4 */
                border_active: (189, 147, 249), /* Purple: #BD93F9 */
                status_bg: (68, 71, 90),        /* Current Line: #44475A */
                status_fg: (248, 248, 242),   /* Foreground: #F8F8F2 */
                cursor_bg: (255, 121, 198),     /* Pink: #FF79C6 */
                cursor_fg: (40, 42, 54),        /* Background: #282A36 */
                selection_bg: (68, 71, 90),     /* Current Line: #44475A */

                mnemonic: (255, 121, 198),       /* Pink: #FF79C6 */
                mnemonic_call: (139, 233, 253),  /* Cyan: #8BE9FD */
                mnemonic_jump: (189, 147, 249),  /* Purple: #BD93F9 */
                mnemonic_ret: (255, 85, 85),     /* Red: #FF5555 */
                register: (255, 184, 108),      /* Orange: #FFB86C */
                immediate: (241, 250, 140),     /* Yellow: #F1FA8C */
                memory_bracket: (98, 114, 164), /* Comment: #6272A4 */
                branch_target: (139, 233, 253), /* Cyan: #8BE9FD */
                source_line: (80, 250, 123),    /* Green: #50FA7B */
                keyword: (255, 121, 198),       /* Pink: #FF79C6 */

                hex_offset: (98, 114, 164),     /* Comment: #6272A4 */
                hex_zero: (68, 71, 90),         /* Dark Selection: #44475A */
                hex_printable: (248, 248, 242), /* Foreground: #F8F8F2 */
                hex_nonprintable: (98, 114, 164),/* Comment: #6272A4 */
                hex_modified: (241, 250, 140),  /* Yellow: #F1FA8C */

                node_border: (189, 147, 249),   /* Purple: #BD93F9 */
                node_header: (68, 71, 90),      /* Current Line: #44475A */
                edge_taken: (80, 250, 123),     /* Green: #50FA7B */
                edge_fallthrough: (255, 85, 85),/* Red: #FF5555 */
                edge_unconditional: (139, 233, 253),/* Cyan: #8BE9FD */

                entropy_low: (80, 250, 123),    /* Green: #50FA7B */
                entropy_mid: (241, 250, 140),   /* Yellow: #F1FA8C */
                entropy_high: (255, 85, 85),    /* Red: #FF5555 */

                modal_bg: (40, 42, 54),         /* Background: #282A36 */
                modal_border: (189, 147, 249),  /* Purple: #BD93F9 */
                modal_selected: (68, 71, 90),   /* Current Line: #44475A */
            },
        }
    }

    /* construct Monokai color scheme preset */
    pub fn monokai() -> Self {
        Self {
            preset: ThemePreset::Monokai,
            palette: Palette {
                background: (39, 40, 34),       /* Background: #272822 */
                foreground: (248, 248, 242),   /* Foreground: #F8F8F2 */
                border: (117, 113, 94),         /* Comment: #75715E */
                border_active: (249, 38, 114),  /* Pink: #F92672 */
                status_bg: (62, 61, 50),        /* Dark Tone */
                status_fg: (248, 248, 242),   /* Foreground: #F8F8F2 */
                cursor_bg: (102, 217, 239),     /* Cyan: #66D9EF */
                cursor_fg: (39, 40, 34),        /* Background: #272822 */
                selection_bg: (73, 72, 62),     /* Selection: #49483E */

                mnemonic: (249, 38, 114),       /* Pink: #F92672 */
                mnemonic_call: (102, 217, 239), /* Cyan: #66D9EF */
                mnemonic_jump: (174, 129, 255), /* Purple: #AE81FF */
                mnemonic_ret: (249, 38, 114),   /* Pink: #F92672 */
                register: (253, 151, 31),       /* Orange: #FD971F */
                immediate: (174, 129, 255),     /* Purple: #AE81FF */
                memory_bracket: (117, 113, 94), /* Comment: #75715E */
                branch_target: (166, 226, 46),  /* Green: #A6E22E */
                source_line: (230, 219, 116),   /* Yellow: #E6DB74 */
                keyword: (249, 38, 114),        /* Pink: #F92672 */

                hex_offset: (117, 113, 94),     /* Comment: #75715E */
                hex_zero: (62, 61, 50),         /* Dark Tone */
                hex_printable: (248, 248, 242), /* Foreground: #F8F8F2 */
                hex_nonprintable: (117, 113, 94),/* Comment: #75715E */
                hex_modified: (230, 219, 116),  /* Yellow: #E6DB74 */

                node_border: (102, 217, 239),   /* Cyan: #66D9EF */
                node_header: (62, 61, 50),
                edge_taken: (166, 226, 46),     /* Green: #A6E22E */
                edge_fallthrough: (249, 38, 114),/* Pink: #F92672 */
                edge_unconditional: (102, 217, 239),/* Cyan: #66D9EF */

                entropy_low: (166, 226, 46),    /* Green: #A6E22E */
                entropy_mid: (230, 219, 116),   /* Yellow: #E6DB74 */
                entropy_high: (249, 38, 114),   /* Pink: #F92672 */

                modal_bg: (39, 40, 34),
                modal_border: (102, 217, 239),
                modal_selected: (73, 72, 62),
            },
        }
    }

    /* construct Gruvbox color scheme preset with warm retro tones */
    pub fn gruvbox() -> Self {
        Self {
            preset: ThemePreset::Gruvbox,
            palette: Palette {
                background: (40, 40, 40),       /* Dark0: #282828 */
                foreground: (235, 219, 178),   /* Light1: #EBDBB2 */
                border: (146, 131, 116),        /* Gray: #928374 */
                border_active: (250, 189, 47),  /* Yellow: #FABD2F */
                status_bg: (60, 56, 54),        /* Dark1: #3C3836 */
                status_fg: (235, 219, 178),   /* Light1: #EBDBB2 */
                cursor_bg: (131, 165, 152),     /* Blue: #83A598 */
                cursor_fg: (40, 40, 40),        /* Dark0: #282828 */
                selection_bg: (80, 73, 69),     /* Dark2: #504945 */

                mnemonic: (251, 73, 52),        /* Red: #FB4934 */
                mnemonic_call: (142, 192, 124), /* Aqua: #8EC07C */
                mnemonic_jump: (211, 134, 155), /* Purple: #D3869B */
                mnemonic_ret: (251, 73, 52),    /* Red: #FB4934 */
                register: (250, 189, 47),       /* Yellow: #FABD2F */
                immediate: (211, 134, 155),     /* Purple: #D3869B */
                memory_bracket: (146, 131, 116),/* Gray: #928374 */
                branch_target: (131, 165, 152), /* Blue: #83A598 */
                source_line: (184, 187, 38),    /* Green: #B8BB26 */
                keyword: (251, 73, 52),         /* Red: #FB4934 */

                hex_offset: (146, 131, 116),    /* Gray: #928374 */
                hex_zero: (60, 56, 54),         /* Dark1: #3C3836 */
                hex_printable: (235, 219, 178), /* Light1: #EBDBB2 */
                hex_nonprintable: (146, 131, 116),/* Gray: #928374 */
                hex_modified: (250, 189, 47),   /* Yellow: #FABD2F */

                node_border: (250, 189, 47),    /* Yellow: #FABD2F */
                node_header: (60, 56, 54),
                edge_taken: (184, 187, 38),     /* Green: #B8BB26 */
                edge_fallthrough: (251, 73, 52),/* Red: #FB4934 */
                edge_unconditional: (142, 192, 124),/* Aqua: #8EC07C */

                entropy_low: (184, 187, 38),    /* Green: #B8BB26 */
                entropy_mid: (250, 189, 47),    /* Yellow: #FABD2F */
                entropy_high: (251, 73, 52),    /* Red: #FB4934 */

                modal_bg: (40, 40, 40),
                modal_border: (250, 189, 47),
                modal_selected: (80, 73, 69),
            },
        }
    }

    /* construct Solarized Dark color scheme preset */
    pub fn solarized() -> Self {
        Self {
            preset: ThemePreset::Solarized,
            palette: Palette {
                background: (0, 43, 54),        /* Base03: #002B36 */
                foreground: (131, 148, 150),   /* Base0: #839496 */
                border: (88, 110, 117),         /* Base01: #586E75 */
                border_active: (38, 139, 210),  /* Blue: #268BD2 */
                status_bg: (7, 54, 66),         /* Base02: #073642 */
                status_fg: (147, 161, 161),    /* Base1: #93A1A1 */
                cursor_bg: (42, 161, 152),      /* Cyan: #2AA198 */
                cursor_fg: (0, 43, 54),         /* Base03: #002B36 */
                selection_bg: (7, 54, 66),      /* Base02: #073642 */

                mnemonic: (38, 139, 210),       /* Blue: #268BD2 */
                mnemonic_call: (42, 161, 152),  /* Cyan: #2AA198 */
                mnemonic_jump: (108, 113, 196), /* Violet: #6C71C4 */
                mnemonic_ret: (220, 50, 47),    /* Red: #DC322F */
                register: (181, 137, 0),        /* Yellow: #B58900 */
                immediate: (211, 54, 130),      /* Magenta: #D33682 */
                memory_bracket: (88, 110, 117), /* Base01: #586E75 */
                branch_target: (42, 161, 152),  /* Cyan: #2AA198 */
                source_line: (133, 153, 0),     /* Green: #859900 */
                keyword: (38, 139, 210),        /* Blue: #268BD2 */

                hex_offset: (88, 110, 117),     /* Base01: #586E75 */
                hex_zero: (7, 54, 66),          /* Base02: #073642 */
                hex_printable: (131, 148, 150), /* Base0: #839496 */
                hex_nonprintable: (88, 110, 117),/* Base01: #586E75 */
                hex_modified: (181, 137, 0),    /* Yellow: #B58900 */

                node_border: (38, 139, 210),    /* Blue: #268BD2 */
                node_header: (7, 54, 66),
                edge_taken: (133, 153, 0),      /* Green: #859900 */
                edge_fallthrough: (220, 50, 47),/* Red: #DC322F */
                edge_unconditional: (42, 161, 152),/* Cyan: #2AA198 */

                entropy_low: (133, 153, 0),     /* Green: #859900 */
                entropy_mid: (181, 137, 0),     /* Yellow: #B58900 */
                entropy_high: (220, 50, 47),    /* Red: #DC322F */

                modal_bg: (0, 43, 54),
                modal_border: (38, 139, 210),
                modal_selected: (7, 54, 66),
            },
        }
    }

    /* select theme by preset enum */
    pub fn from_preset(preset: ThemePreset) -> Self {
        match preset {
            ThemePreset::Nord => Self::nord(),
            ThemePreset::Dracula => Self::dracula(),
            ThemePreset::Monokai => Self::monokai(),
            ThemePreset::Gruvbox => Self::gruvbox(),
            ThemePreset::Solarized => Self::solarized(),
            ThemePreset::Custom => Self::load_user_config().unwrap_or_else(Self::nord),
        }
    }

    /* match theme by name string (case-insensitive) */
    pub fn from_preset_name(name: &str) -> Option<Self> {
        let n = name.trim().to_lowercase();
        match n.as_str() {
            "nord" => Some(Self::nord()),
            "dracula" => Some(Self::dracula()),
            "monokai" => Some(Self::monokai()),
            "gruvbox" => Some(Self::gruvbox()),
            "solarized" => Some(Self::solarized()),
            "custom" => Some(Self::load_user_config().unwrap_or_else(Self::nord)),
            _ => None,
        }
    }

    /* cycle to the next built-in theme preset */
    pub fn cycle_next(&self) -> Self {
        match self.preset {
            ThemePreset::Nord => Self::dracula(),
            ThemePreset::Dracula => Self::monokai(),
            ThemePreset::Monokai => Self::gruvbox(),
            ThemePreset::Gruvbox => Self::solarized(),
            ThemePreset::Solarized => Self::nord(),
            ThemePreset::Custom => Self::nord(),
        }
    }

    /*
     * load custom user theme from ~/.config/velf/theme.toml or $XDG_CONFIG_HOME/velf/theme.toml.
     * Allows custom color overrides without recompilation.
     */
    pub fn load_user_config() -> Option<Self> {
        let config_path = get_user_theme_path()?;
        if !config_path.exists() {
            return None;
        }

        let contents = fs::read_to_string(&config_path).ok()?;
        let palette: Palette = toml::from_str(&contents).ok()?;
        Some(Self {
            preset: ThemePreset::Custom,
            palette,
        })
    }
}

/* resolve filesystem path to ~/.config/velf/theme.toml */
fn get_user_theme_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("velf").join("theme.toml"));
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(PathBuf::from(home).join(".config").join("velf").join("theme.toml"));
        }
    }

    None
}
