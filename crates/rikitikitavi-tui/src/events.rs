use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent};
use std::time::Duration;

/// Poll for terminal events with a timeout.
pub fn poll_event(timeout: Duration) -> Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Extract a key event if the event is a key press.
pub fn as_key_press(event: &Event) -> Option<&KeyEvent> {
    if let Event::Key(key) = event {
        if key.kind == crossterm::event::KeyEventKind::Press {
            return Some(key);
        }
    }
    None
}
