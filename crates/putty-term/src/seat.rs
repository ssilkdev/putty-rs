use std::io::{self, Read, Write};
use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SeatError {
    #[error("Terminal I/O error: {0}")]
    Io(#[from] io::Error),
}

pub struct ConsoleSeat {
    is_raw: bool,
}

impl ConsoleSeat {
    pub fn new() -> Result<Self, SeatError> {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::System::Console::*;
            let stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
            let mut mode: u32 = 0;
            if GetConsoleMode(stdout_handle, &mut mode) != 0 {
                // Enable Virtual Terminal Processing (VT100 escape sequences on Windows)
                mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
                SetConsoleMode(stdout_handle, mode);
            }
        }

        Ok(Self { is_raw: false })
    }

    pub fn enter_raw_mode(&mut self) -> Result<(), SeatError> {
        if !self.is_raw {
            enable_raw_mode()?;
            self.is_raw = true;
        }
        Ok(())
    }

    pub fn exit_raw_mode(&mut self) -> Result<(), SeatError> {
        if self.is_raw {
            disable_raw_mode()?;
            self.is_raw = false;
        }
        Ok(())
    }

    pub fn write_output(&self, data: &[u8]) -> Result<(), SeatError> {
        let mut stdout = io::stdout().lock();
        stdout.write_all(data)?;
        stdout.flush()?;
        Ok(())
    }

    pub fn read_input(&self, buf: &mut [u8]) -> Result<usize, SeatError> {
        let mut stdin = io::stdin().lock();
        let n = stdin.read(buf)?;
        Ok(n)
    }

    pub fn get_size(&self) -> (u16, u16) {
        crossterm::terminal::size().unwrap_or((80, 24))
    }
}

impl Drop for ConsoleSeat {
    fn drop(&mut self) {
        let _ = self.exit_raw_mode();
    }
}
