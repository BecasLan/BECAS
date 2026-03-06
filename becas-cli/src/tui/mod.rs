//! # BECAS TUI — Terminal User Interface
//!
//! Beautiful, interactive terminal interface for BECAS.
//!
//! ## Screens
//! - Dashboard: Service status, system metrics
//! - Marketplace: Browse and install templates
//! - Logs: Live log viewer
//! - Settings: Configuration

mod app;
mod ui;
mod event;

pub use app::App;
pub use ui::draw;
pub use event::{Event, EventHandler};

use std::io;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

/// Run the TUI application
pub async fn run(data_dir: &str) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and event handler
    let mut app = App::new(data_dir.to_string());
    let event_handler = EventHandler::new(250);

    // Initial data load
    app.load_services().await;
    app.load_system_metrics();

    // Main loop
    let result = run_app(&mut terminal, &mut app, event_handler).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
    mut event_handler: EventHandler,
) -> anyhow::Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| ui::draw(frame, app))?;

        // Handle events
        match event_handler.next().await? {
            Event::Tick => {
                app.on_tick().await;
            }
            Event::Key(key_event) => {
                if app.handle_key(key_event).await {
                    break; // Quit signal
                }
            }
            Event::Mouse(_) => {}
            Event::Resize(_, _) => {}
        }
    }

    Ok(())
}
