pub mod vt;
pub mod seat;

pub use vt::{TerminalEmulator, AnsiParser, Cell};
pub use seat::{ConsoleSeat, SeatError};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_terminal_emulator_basic_output() {
        let mut term = TerminalEmulator::new(24, 80);
        AnsiParser::parse(b"Hello PuTTY Rust!\r\nSecond line", &mut term);

        let row0 = term.get_row_text(0).unwrap();
        assert!(row0.starts_with("Hello PuTTY Rust!"));

        let row1 = term.get_row_text(1).unwrap();
        assert!(row1.starts_with("Second line"));
    }

    #[test]
    fn test_terminal_emulator_csi_clear() {
        let mut term = TerminalEmulator::new(24, 80);
        AnsiParser::parse(b"Temporary text", &mut term);
        assert!(term.get_row_text(0).unwrap().starts_with("Temporary text"));

        // CSI 2 J clears screen
        AnsiParser::parse(b"\x1b[2J", &mut term);
        assert_eq!(term.cursor_row, 0);
        assert_eq!(term.cursor_col, 0);
        assert!(term.get_row_text(0).unwrap().trim().is_empty());
    }
}
