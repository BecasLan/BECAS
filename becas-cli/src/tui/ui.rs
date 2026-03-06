//! UI rendering for BECAS TUI

use ratatui::{
    prelude::*,
    widgets::*,
    symbols,
};
use super::app::{App, Screen, Popup, InputMode, HISTORY_SIZE, NewServiceForm};

// Colors - BECAS Theme (Dark Red/Crimson)
const PRIMARY: Color = Color::Rgb(220, 50, 47);      // Crimson
const SECONDARY: Color = Color::Rgb(181, 137, 0);   // Gold
const SUCCESS: Color = Color::Rgb(133, 153, 0);     // Green
const WARNING: Color = Color::Rgb(203, 75, 22);     // Orange
const DANGER: Color = Color::Rgb(211, 1, 2);        // Red
const INFO: Color = Color::Rgb(38, 139, 210);       // Blue
const MUTED: Color = Color::Rgb(88, 110, 117);      // Gray
const BG_DARK: Color = Color::Rgb(0, 43, 54);       // Dark background
const FG: Color = Color::Rgb(253, 246, 227);        // Light text

/// Main draw function
pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    
    // Main layout: header, content, footer
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Min(10),    // Content
            Constraint::Length(3),  // Footer
        ])
        .split(area);

    draw_header(frame, app, chunks[0]);
    draw_content(frame, app, chunks[1]);
    draw_footer(frame, app, chunks[2]);

    // Draw popup if active
    if let Some(popup) = &app.popup {
        draw_popup(frame, popup, area);
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let tabs: Vec<Line> = Screen::all()
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if *s == app.screen {
                Style::default().fg(PRIMARY).bold()
            } else {
                Style::default().fg(MUTED)
            };
            Line::from(format!(" {} {} ", i + 1, s.title())).style(style)
        })
        .collect();

    let title = Line::from(vec![
        Span::styled("🛡️  ", Style::default().fg(PRIMARY)),
        Span::styled("BECAS", Style::default().fg(PRIMARY).bold()),
        Span::styled(" — Better Call Safe Way", Style::default().fg(MUTED)),
    ]);

    let header = Paragraph::new(vec![title, Line::from("")])
        .block(Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(MUTED)));

    frame.render_widget(header, area);

    // Render tabs on right side
    let tabs_area = Rect {
        x: area.x + area.width.saturating_sub(60),
        y: area.y,
        width: 60.min(area.width),
        height: 1,
    };
    
    let screens = Screen::all();
    let tab_titles: Vec<&str> = screens.iter().map(|s| s.title()).collect();
    let tab_widget = Tabs::new(tab_titles)
        .select(screens.iter().position(|s| *s == app.screen).unwrap_or(0))
        .style(Style::default().fg(MUTED))
        .highlight_style(Style::default().fg(PRIMARY).bold())
        .divider("│");
    
    frame.render_widget(tab_widget, tabs_area);
}

fn draw_content(frame: &mut Frame, app: &App, area: Rect) {
    match app.screen {
        Screen::Dashboard => draw_dashboard(frame, app, area),
        Screen::Services => draw_services(frame, app, area),
        Screen::Marketplace => draw_marketplace(frame, app, area),
        Screen::Logs => draw_logs(frame, app, area),
        Screen::Network => draw_network(frame, app, area),
        Screen::Help => draw_help(frame, area),
    }
}

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    // Check for status message first
    let footer_text = if let Some((msg, _)) = &app.status_message {
        msg.clone()
    } else {
        match app.screen {
            Screen::Dashboard => "r: Refresh | Tab: Next Screen | q: Quit".to_string(),
            Screen::Services => "↑↓: Select | Enter: Start/Stop | n: New | t: Tunnel | l: Logs | q: Quit".to_string(),
            Screen::Marketplace => "↑↓: Select | Enter: Install | /: Search | q: Quit".to_string(),
            Screen::Logs => "↑↓: Scroll | c: Clear Filter | G: End | g: Start | q: Quit".to_string(),
            Screen::Network => "r: Refresh | q: Quit".to_string(),
            Screen::Help => "q: Quit | Tab: Next Screen".to_string(),
        }
    };

    let style = if app.status_message.is_some() {
        Style::default().fg(SUCCESS).bold()
    } else {
        Style::default().fg(MUTED)
    };

    let footer = Paragraph::new(footer_text)
        .style(style)
        .block(Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(MUTED)));

    frame.render_widget(footer, area);
}

fn draw_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Left side: System metrics
    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Metrics
            Constraint::Min(5),     // Services summary
        ])
        .split(chunks[0]);

    draw_metrics_panel(frame, app, left_chunks[0]);
    draw_services_summary(frame, app, left_chunks[1]);

    // Right side: Quick actions / Recent activity
    draw_quick_panel(frame, app, chunks[1]);
}

fn draw_metrics_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" 📊 System Metrics ", Style::default().fg(INFO).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let metrics = &app.metrics;
    
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),  // CPU sparkline + gauge
            Constraint::Length(3),  // RAM sparkline + gauge
        ])
        .split(inner);

    // CPU section
    let cpu_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(25)])
        .split(chunks[0]);

    // CPU gauge
    let cpu_color = if metrics.cpu_usage > 80.0 { DANGER } else if metrics.cpu_usage > 50.0 { WARNING } else { SUCCESS };
    let cpu_label = format!("CPU {:.1}% ({} cores)", metrics.cpu_usage, metrics.cpu_cores);
    let cpu_gauge = Gauge::default()
        .gauge_style(Style::default().fg(cpu_color).add_modifier(Modifier::BOLD))
        .percent(metrics.cpu_usage.min(100.0) as u16)
        .label(cpu_label);
    frame.render_widget(cpu_gauge, cpu_chunks[0]);

    // CPU sparkline
    let cpu_sparkline = Sparkline::default()
        .data(&app.cpu_history)
        .max(100)
        .style(Style::default().fg(cpu_color));
    frame.render_widget(cpu_sparkline, cpu_chunks[1]);

    // RAM section
    let ram_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(25)])
        .split(chunks[1]);

    // RAM gauge
    let ram_percent = if metrics.ram_total_mb > 0 {
        (metrics.ram_used_mb as f64 / metrics.ram_total_mb as f64 * 100.0) as u16
    } else { 0 };
    let ram_color = if ram_percent > 80 { DANGER } else if ram_percent > 50 { WARNING } else { INFO };
    let ram_label = format!("RAM {}MB/{}MB", metrics.ram_used_mb, metrics.ram_total_mb);
    let ram_gauge = Gauge::default()
        .gauge_style(Style::default().fg(ram_color).add_modifier(Modifier::BOLD))
        .percent(ram_percent.min(100))
        .label(ram_label);
    frame.render_widget(ram_gauge, ram_chunks[0]);

    // RAM sparkline
    let ram_sparkline = Sparkline::default()
        .data(&app.ram_history)
        .max(100)
        .style(Style::default().fg(ram_color));
    frame.render_widget(ram_sparkline, ram_chunks[1]);
}

fn draw_services_summary(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" 📦 Services ", Style::default().fg(SECONDARY).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let running = app.metrics.services_running;
    let total = app.metrics.services_total;
    
    let text = vec![
        Line::from(vec![
            Span::styled("🟢 Running: ", Style::default().fg(SUCCESS)),
            Span::styled(format!("{}", running), Style::default().fg(FG).bold()),
        ]),
        Line::from(vec![
            Span::styled("📦 Total:   ", Style::default().fg(MUTED)),
            Span::styled(format!("{}", total), Style::default().fg(FG)),
        ]),
        Line::from(""),
        Line::from(Span::styled(
            "Press 2 or Tab to manage services",
            Style::default().fg(MUTED).italic()
        )),
    ];

    let paragraph = Paragraph::new(text).block(Block::default().padding(Padding::horizontal(1)));
    frame.render_widget(paragraph, inner);
}

fn draw_quick_panel(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" ⚡ Quick Actions ", Style::default().fg(WARNING).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items = vec![
        Line::from(vec![
            Span::styled("  [2] ", Style::default().fg(PRIMARY)),
            Span::raw("Manage Services"),
        ]),
        Line::from(vec![
            Span::styled("  [3] ", Style::default().fg(PRIMARY)),
            Span::raw("Browse Marketplace"),
        ]),
        Line::from(vec![
            Span::styled("  [4] ", Style::default().fg(PRIMARY)),
            Span::raw("View Logs"),
        ]),
        Line::from(vec![
            Span::styled("  [5] ", Style::default().fg(PRIMARY)),
            Span::raw("Network & NAT"),
        ]),
        Line::from(""),
        Line::from(Span::styled("─".repeat(30), Style::default().fg(MUTED))),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Tip: ", Style::default().fg(SECONDARY)),
            Span::styled("Use Tab to switch screens", Style::default().fg(MUTED)),
        ]),
    ];

    let paragraph = Paragraph::new(items).block(Block::default().padding(Padding::new(1, 1, 1, 0)));
    frame.render_widget(paragraph, inner);
}

fn draw_services(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" 📦 Services ", Style::default().fg(SECONDARY).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    if app.services.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No services deployed yet", Style::default().fg(MUTED))),
            Line::from(""),
            Line::from(Span::styled("  Go to Marketplace (3) to install a service", Style::default().fg(INFO))),
        ]).block(block);
        frame.render_widget(empty, area);
        return;
    }

    let rows: Vec<Row> = app.services.iter().enumerate().map(|(i, svc)| {
        let status_style = match svc.status.as_str() {
            "Running" => Style::default().fg(SUCCESS),
            "Stopped" | "Deployed" => Style::default().fg(MUTED),
            _ => Style::default().fg(DANGER),
        };
        let status_icon = match svc.status.as_str() {
            "Running" => "🟢",
            "Stopped" | "Deployed" => "⚫",
            _ => "🔴",
        };

        let selected = i == app.selected_service;
        let row_style = if selected {
            Style::default().bg(Color::Rgb(30, 30, 40))
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(format!("{} {}", status_icon, svc.name)).style(if selected { Style::default().fg(FG).bold() } else { Style::default().fg(FG) }),
            Cell::from(svc.status.clone()).style(status_style),
            Cell::from(svc.service_type.clone()).style(Style::default().fg(MUTED)),
            Cell::from(svc.pid.map_or("-".to_string(), |p| p.to_string())).style(Style::default().fg(MUTED)),
            Cell::from(format!("{}%", svc.cpu_limit)),
            Cell::from(format!("{}MB", svc.ram_limit_mb)),
            Cell::from(svc.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")),
        ]).style(row_style)
    }).collect();

    let header = Row::new(vec!["SERVICE", "STATUS", "TYPE", "PID", "CPU", "RAM", "PORTS"])
        .style(Style::default().fg(MUTED).bold())
        .bottom_margin(1);

    let table = Table::new(rows, [
        Constraint::Min(20),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(12),
    ])
    .header(header)
    .block(block)
    .row_highlight_style(Style::default().bg(Color::Rgb(40, 40, 50)));

    frame.render_widget(table, area);
}

fn draw_marketplace(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    // Template list
    let block = Block::default()
        .title(Span::styled(" 🏪 Marketplace ", Style::default().fg(PRIMARY).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let rows: Vec<Row> = app.templates.iter().enumerate().map(|(i, tmpl)| {
        let selected = i == app.selected_template;
        let row_style = if selected {
            Style::default().bg(Color::Rgb(30, 30, 40))
        } else {
            Style::default()
        };

        Row::new(vec![
            Cell::from(tmpl.name.clone()).style(if selected { Style::default().fg(FG).bold() } else { Style::default().fg(FG) }),
            Cell::from(tmpl.category.clone()).style(Style::default().fg(SECONDARY)),
            Cell::from(format!("⬇{}", tmpl.downloads)).style(Style::default().fg(MUTED)),
            Cell::from(format!("⭐{:.1}", tmpl.rating)).style(Style::default().fg(WARNING)),
        ]).style(row_style)
    }).collect();

    let header = Row::new(vec!["TEMPLATE", "CATEGORY", "DOWNLOADS", "RATING"])
        .style(Style::default().fg(MUTED).bold())
        .bottom_margin(1);

    let table = Table::new(rows, [
        Constraint::Min(15),
        Constraint::Length(12),
        Constraint::Length(10),
        Constraint::Length(8),
    ])
    .header(header)
    .block(block);

    frame.render_widget(table, chunks[0]);

    // Template details
    draw_template_details(frame, app, chunks[1]);
}

fn draw_template_details(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" 📋 Details ", Style::default().fg(INFO).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    if let Some(tmpl) = app.templates.get(app.selected_template) {
        let text = vec![
            Line::from(Span::styled(&tmpl.name, Style::default().fg(FG).bold())),
            Line::from(""),
            Line::from(vec![
                Span::styled("Category: ", Style::default().fg(MUTED)),
                Span::styled(&tmpl.category, Style::default().fg(SECONDARY)),
            ]),
            Line::from(vec![
                Span::styled("Downloads: ", Style::default().fg(MUTED)),
                Span::styled(format!("{}", tmpl.downloads), Style::default().fg(FG)),
            ]),
            Line::from(vec![
                Span::styled("Rating: ", Style::default().fg(MUTED)),
                Span::styled(format!("{:.1} ⭐", tmpl.rating), Style::default().fg(WARNING)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Description:", Style::default().fg(MUTED))),
            Line::from(Span::raw(&tmpl.description)),
            Line::from(""),
            Line::from(Span::styled("─".repeat(25), Style::default().fg(MUTED))),
            Line::from(""),
            Line::from(vec![
                Span::styled("Press ", Style::default().fg(MUTED)),
                Span::styled("Enter", Style::default().fg(PRIMARY).bold()),
                Span::styled(" to install", Style::default().fg(MUTED)),
            ]),
        ];

        let paragraph = Paragraph::new(text)
            .wrap(Wrap { trim: true })
            .block(Block::default().padding(Padding::horizontal(1)));
        frame.render_widget(paragraph, inner);
    }
}

fn draw_logs(frame: &mut Frame, app: &App, area: Rect) {
    let title = if let Some(ref filter) = app.log_filter {
        format!(" 📋 Logs — {} ", filter)
    } else {
        " 📋 Logs ".to_string()
    };

    let block = Block::default()
        .title(Span::styled(title, Style::default().fg(INFO).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    if app.logs.is_empty() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled("  No logs available", Style::default().fg(MUTED))),
            Line::from(""),
            Line::from(Span::styled("  Start a service to see logs here", Style::default().fg(INFO))),
        ]).block(block);
        frame.render_widget(empty, area);
        return;
    }

    let logs: Vec<ListItem> = app.logs.iter().map(|log| {
        let level_style = match log.level.as_str() {
            "ERROR" => Style::default().fg(DANGER),
            "WARN" => Style::default().fg(WARNING),
            "INFO" => Style::default().fg(INFO),
            _ => Style::default().fg(MUTED),
        };

        ListItem::new(Line::from(vec![
            Span::styled(&log.timestamp, Style::default().fg(MUTED)),
            Span::raw(" "),
            Span::styled(&log.level, level_style),
            Span::raw(" "),
            Span::styled(&log.service, Style::default().fg(SECONDARY)),
            Span::raw(" "),
            Span::raw(&log.message),
        ]))
    }).collect();

    let list = List::new(logs).block(block);
    frame.render_widget(list, area);
}

fn draw_network(frame: &mut Frame, app: &App, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" 🌐 Network & NAT ", Style::default().fg(INFO).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let text = vec![
        Line::from(""),
        Line::from(Span::styled("  NAT Detection", Style::default().fg(FG).bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled("    Status: ", Style::default().fg(MUTED)),
            Span::styled("Ready to check", Style::default().fg(WARNING)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Run 'becas nat' in terminal for full detection", Style::default().fg(MUTED))),
        Line::from(""),
        Line::from(Span::styled("─".repeat(40), Style::default().fg(MUTED))),
        Line::from(""),
        Line::from(Span::styled("  Connection Methods:", Style::default().fg(FG).bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled("    ✅ ", Style::default().fg(SUCCESS)),
            Span::raw("Cloudflare Tunnel (Primary)"),
        ]),
        Line::from(vec![
            Span::styled("    ✅ ", Style::default().fg(SUCCESS)),
            Span::raw("BECAS Relay Server"),
        ]),
        Line::from(vec![
            Span::styled("    ✅ ", Style::default().fg(SUCCESS)),
            Span::raw("STUN/TURN (P2P)"),
        ]),
        Line::from(vec![
            Span::styled("    ✅ ", Style::default().fg(SUCCESS)),
            Span::raw("LAN Mesh"),
        ]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(Span::styled(" ❓ Help ", Style::default().fg(INFO).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(MUTED));

    let text = vec![
        Line::from(""),
        Line::from(Span::styled("  Keyboard Shortcuts", Style::default().fg(FG).bold())),
        Line::from(""),
        Line::from(vec![Span::styled("    1-5    ", Style::default().fg(PRIMARY)), Span::raw("Switch screens")]),
        Line::from(vec![Span::styled("    Tab    ", Style::default().fg(PRIMARY)), Span::raw("Next screen")]),
        Line::from(vec![Span::styled("    ↑/↓    ", Style::default().fg(PRIMARY)), Span::raw("Navigate list")]),
        Line::from(vec![Span::styled("    Enter  ", Style::default().fg(PRIMARY)), Span::raw("Select/Confirm")]),
        Line::from(vec![Span::styled("    r      ", Style::default().fg(PRIMARY)), Span::raw("Refresh data")]),
        Line::from(vec![Span::styled("    q      ", Style::default().fg(PRIMARY)), Span::raw("Quit")]),
        Line::from(""),
        Line::from(Span::styled("  Services Screen", Style::default().fg(FG).bold())),
        Line::from(""),
        Line::from(vec![Span::styled("    s      ", Style::default().fg(PRIMARY)), Span::raw("Start/Stop service")]),
        Line::from(vec![Span::styled("    l      ", Style::default().fg(PRIMARY)), Span::raw("View logs")]),
        Line::from(""),
        Line::from(Span::styled("  Marketplace Screen", Style::default().fg(FG).bold())),
        Line::from(""),
        Line::from(vec![Span::styled("    i      ", Style::default().fg(PRIMARY)), Span::raw("Install template")]),
        Line::from(vec![Span::styled("    /      ", Style::default().fg(PRIMARY)), Span::raw("Search")]),
    ];

    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

fn draw_popup(frame: &mut Frame, popup: &Popup, area: Rect) {
    match popup {
        Popup::Confirm { title, message, .. } => {
            let popup_area = centered_rect(50, 30, area);
            frame.render_widget(Clear, popup_area);
            
            let block = Block::default()
                .title(Span::styled(format!(" {} ", title), Style::default().fg(WARNING).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(WARNING))
                .style(Style::default().bg(Color::Rgb(20, 20, 30)));

            let text = vec![
                Line::from(""),
                Line::from(Span::raw(message.as_str())),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [Y]es  ", Style::default().fg(SUCCESS).bold()),
                    Span::styled("  [N]o  ", Style::default().fg(DANGER).bold()),
                ]),
            ];

            let paragraph = Paragraph::new(text)
                .block(block)
                .alignment(Alignment::Center);
            frame.render_widget(paragraph, popup_area);
        }
        Popup::Info { title, message } => {
            let popup_area = centered_rect(50, 30, area);
            frame.render_widget(Clear, popup_area);
            
            let block = Block::default()
                .title(Span::styled(format!(" {} ", title), Style::default().fg(INFO).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(INFO))
                .style(Style::default().bg(Color::Rgb(20, 20, 30)));

            let text = vec![
                Line::from(""),
                Line::from(Span::raw(message.as_str())),
                Line::from(""),
                Line::from(Span::styled("Press any key to close", Style::default().fg(MUTED))),
            ];

            let paragraph = Paragraph::new(text)
                .block(block)
                .alignment(Alignment::Center);
            frame.render_widget(paragraph, popup_area);
        }
        Popup::Input { title, .. } => {
            let popup_area = centered_rect(50, 30, area);
            frame.render_widget(Clear, popup_area);
            
            let block = Block::default()
                .title(Span::styled(format!(" {} ", title), Style::default().fg(INFO).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(INFO))
                .style(Style::default().bg(Color::Rgb(20, 20, 30)));

            frame.render_widget(block, popup_area);
        }
        Popup::NewService(form) => {
            let popup_area = centered_rect(60, 50, area);
            frame.render_widget(Clear, popup_area);
            
            let block = Block::default()
                .title(Span::styled(" ➕ New Service ", Style::default().fg(SUCCESS).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(SUCCESS))
                .style(Style::default().bg(Color::Rgb(20, 20, 30)));

            let inner = block.inner(popup_area);
            frame.render_widget(block, popup_area);

            let fields = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints([
                    Constraint::Length(3),  // Name
                    Constraint::Length(3),  // Command
                    Constraint::Length(3),  // Args
                    Constraint::Length(3),  // Port
                    Constraint::Length(2),  // Spacer
                    Constraint::Length(2),  // Help
                ])
                .split(inner);

            for i in 0..4 {
                let is_active = form.active_field == i;
                let border_color = if is_active { PRIMARY } else { MUTED };
                let label = form.field_name(i);
                let value = form.field_value(i);
                
                let input = Paragraph::new(value)
                    .style(Style::default().fg(FG))
                    .block(Block::default()
                        .title(Span::styled(format!(" {} ", label), Style::default().fg(if is_active { PRIMARY } else { MUTED })))
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(border_color)));
                
                frame.render_widget(input, fields[i]);
            }

            // Help text
            let help = Paragraph::new(vec![
                Line::from(vec![
                    Span::styled("Tab", Style::default().fg(PRIMARY)),
                    Span::raw(": Next field  "),
                    Span::styled("Enter", Style::default().fg(SUCCESS)),
                    Span::raw(": Create  "),
                    Span::styled("Esc", Style::default().fg(DANGER)),
                    Span::raw(": Cancel"),
                ]),
            ]).alignment(Alignment::Center);
            frame.render_widget(help, fields[5]);
        }
        Popup::TunnelInfo { service, url } => {
            let popup_area = centered_rect(70, 40, area);
            frame.render_widget(Clear, popup_area);
            
            let block = Block::default()
                .title(Span::styled(" 🌐 Tunnel Active ", Style::default().fg(SUCCESS).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(SUCCESS))
                .style(Style::default().bg(Color::Rgb(20, 20, 30)));

            let text = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Service: ", Style::default().fg(MUTED)),
                    Span::styled(service, Style::default().fg(FG).bold()),
                ]),
                Line::from(""),
                Line::from(Span::styled("Public URL:", Style::default().fg(MUTED))),
                Line::from(""),
                Line::from(Span::styled(url, Style::default().fg(SUCCESS).bold().underlined())),
                Line::from(""),
                Line::from(""),
                Line::from(Span::styled("Share this URL to access your service from anywhere!", Style::default().fg(INFO))),
                Line::from(""),
                Line::from(Span::styled("Press Enter or Esc to close", Style::default().fg(MUTED))),
            ];

            let paragraph = Paragraph::new(text)
                .block(block)
                .alignment(Alignment::Center);
            frame.render_widget(paragraph, popup_area);
        }
    }
}

/// Helper to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
