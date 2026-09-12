use anyhow::Result;
use crossterm::event::{self, Event, KeyEvent, MouseEvent};
use std::time::Duration;

/// Poll for terminal events with a timeout.
pub fn poll_event(timeout: Duration) -> Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Key event for `Press` and `Repeat` kinds; `Release` (kitty protocol) is filtered out.
pub fn as_key_press(event: &Event) -> Option<&KeyEvent> {
    if let Event::Key(key) = event
        && key.kind != crossterm::event::KeyEventKind::Release
    {
        return Some(key);
    }
    None
}

/// Extract a mouse event from a terminal event.
pub const fn as_mouse_event(event: &Event) -> Option<&MouseEvent> {
    if let Event::Mouse(mouse) = event {
        return Some(mouse);
    }
    None
}
