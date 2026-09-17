#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub fg_color: u8,
    pub bg_color: u8,
    pub bold: bool,
    pub underline: bool,
    pub reverse: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: ' ',
            fg_color: 7, // Default light gray
            bg_color: 0, // Default black
            bold: false,
            underline: false,
            reverse: false,
        }
    }
}

pub struct TerminalEmulator {
    pub rows: usize,
    pub cols: usize,
    pub cursor_row: usize,
    pub cursor_col: usize,
    pub grid: Vec<Vec<Cell>>,
    pub active_fg: u8,
    pub active_bg: u8,
    pub bold: bool,
}

impl TerminalEmulator {
    pub fn new(rows: usize, cols: usize) -> Self {
        let grid = vec![vec![Cell::default(); cols]; rows];
        Self {
            rows,
            cols,
            cursor_row: 0,
            cursor_col: 0,
            grid,
            active_fg: 7,
            active_bg: 0,
            bold: false,
        }
    }

    pub fn resize(&mut self, new_rows: usize, new_cols: usize) {
        let mut new_grid = vec![vec![Cell::default(); new_cols]; new_rows];
        for r in 0..self.rows.min(new_rows) {
            for c in 0..self.cols.min(new_cols) {
                new_grid[r][c] = self.grid[r][c].clone();
            }
        }
        self.rows = new_rows;
        self.cols = new_cols;
        self.cursor_row = self.cursor_row.min(new_rows.saturating_sub(1));
        self.cursor_col = self.cursor_col.min(new_cols.saturating_sub(1));
        self.grid = new_grid;
    }

    pub fn process_byte(&mut self, b: u8) {
        match b {
            b'\r' => {
                self.cursor_col = 0;
            }
            b'\n' => {
                if self.cursor_row + 1 >= self.rows {
                    self.scroll_up();
                } else {
                    self.cursor_row += 1;
                }
            }
            b'\x08' => { // Backspace
                if self.cursor_col > 0 {
                    self.cursor_col -= 1;
                }
            }
            b'\t' => { // Tab
                self.cursor_col = (self.cursor_col + 8) & !7;
                if self.cursor_col >= self.cols {
                    self.cursor_col = self.cols - 1;
                }
            }
            0x20..=0x7e => {
                let ch = b as char;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    if self.cursor_row + 1 >= self.rows {
                        self.scroll_up();
                    } else {
                        self.cursor_row += 1;
                    }
                }
                self.grid[self.cursor_row][self.cursor_col] = Cell {
                    ch,
                    fg_color: self.active_fg,
                    bg_color: self.active_bg,
                    bold: self.bold,
                    underline: false,
                    reverse: false,
                };
                self.cursor_col += 1;
            }
            _ => {}
        }
    }

    fn scroll_up(&mut self) {
        if self.rows > 1 {
            self.grid.remove(0);
            self.grid.push(vec![Cell::default(); self.cols]);
        }
    }

    pub fn get_row_text(&self, row: usize) -> Option<String> {
        if row < self.rows {
            Some(self.grid[row].iter().map(|c| c.ch).collect())
        } else {
            None
        }
    }
}

pub struct AnsiParser;

impl AnsiParser {
    pub fn parse(input: &[u8], term: &mut TerminalEmulator) {
        let mut i = 0;
        while i < input.len() {
            if input[i] == 0x1b && i + 1 < input.len() && input[i + 1] == b'[' {
                // CSI sequence
                let mut j = i + 2;
                while j < input.len() && (input[j] >= b'0' && input[j] <= b'?' || input[j] == b';') {
                    j += 1;
                }
                if j < input.len() {
                    let cmd = input[j];
                    let params = &input[i + 2..j];
                    Self::handle_csi(cmd, params, term);
                    i = j + 1;
                    continue;
                }
            }
            term.process_byte(input[i]);
            i += 1;
        }
    }

    fn handle_csi(cmd: u8, _params: &[u8], term: &mut TerminalEmulator) {
        match cmd {
            b'H' | b'f' => {
                // Cursor Home
                term.cursor_row = 0;
                term.cursor_col = 0;
            }
            b'J' => {
                // Clear screen
                for row in &mut term.grid {
                    for cell in row {
                        *cell = Cell::default();
                    }
                }
                term.cursor_row = 0;
                term.cursor_col = 0;
            }
            b'm' => {
                // SGR
            }
            _ => {}
        }
    }
}
