//! Optional terminal UI (ratatui): a response viewer with collapsible JSON
//! and a history browser. Opt-in only (`--tui`, `curly tui`); plain output
//! stays the default, and the TUI refuses to start without a terminal.
//!
//! Exchanges shown here are already redacted (history is stored redacted;
//! `run --tui` shows secrets only with `--show-secrets`).

use std::collections::BTreeSet;
use std::io::IsTerminal;

use anyhow::{Result, bail};
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs};
use serde_json::Value;

use crate::curlexec::Exchange;
use crate::history::Entry;

/// What a container line opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bracket {
    Object,
    Array,
}

impl Bracket {
    fn chars(self) -> (char, char) {
        match self {
            Bracket::Object => ('{', '}'),
            Bracket::Array => ('[', ']'),
        }
    }
}

/// One rendered line of a JSON document.
#[derive(Debug, Clone, PartialEq)]
enum Row {
    /// `key: {` or `[`; `close` is the index of the matching closing row.
    Open {
        bracket: Bracket,
        len: usize,
        close: usize,
    },
    /// `}` or `]`.
    Close(Bracket),
    /// A scalar, already formatted as JSON.
    Leaf(Value),
}

#[derive(Debug, Clone, PartialEq)]
struct TreeLine {
    depth: usize,
    key: Option<String>,
    row: Row,
    comma: bool,
}

/// A JSON document as foldable lines.
#[derive(Debug, Clone, Default)]
pub struct JsonTree {
    lines: Vec<TreeLine>,
    collapsed: BTreeSet<usize>,
}

impl JsonTree {
    /// Flattens `v` into lines.
    pub fn new(v: &Value) -> JsonTree {
        let mut t = JsonTree::default();
        t.push(v, None, 0, false);
        t
    }

    fn push(&mut self, v: &Value, key: Option<String>, depth: usize, comma: bool) {
        let children: Vec<(Option<String>, &Value)> = match v {
            Value::Object(m) => m.iter().map(|(k, v)| (Some(k.clone()), v)).collect(),
            Value::Array(a) => a.iter().map(|v| (None, v)).collect(),
            other => {
                self.lines.push(TreeLine {
                    depth,
                    key,
                    row: Row::Leaf(other.clone()),
                    comma,
                });
                return;
            }
        };
        let bracket = if v.is_object() {
            Bracket::Object
        } else {
            Bracket::Array
        };
        let open = self.lines.len();
        self.lines.push(TreeLine {
            depth,
            key,
            row: Row::Open {
                bracket,
                len: children.len(),
                close: 0,
            },
            comma: false,
        });
        let n = children.len();
        for (i, (k, child)) in children.into_iter().enumerate() {
            self.push(child, k, depth + 1, i + 1 < n);
        }
        let close = self.lines.len();
        self.lines.push(TreeLine {
            depth,
            key: None,
            row: Row::Close(bracket),
            comma,
        });
        if let Row::Open { close: c, .. } = &mut self.lines[open].row {
            *c = close;
        }
    }

    /// Indices of lines not hidden inside a collapsed container.
    pub fn visible(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.lines.len() {
            out.push(i);
            i = match &self.lines[i].row {
                Row::Open { close, .. } if self.collapsed.contains(&i) => close + 1,
                _ => i + 1,
            };
        }
        out
    }

    /// Whether line `i` opens a container.
    pub fn is_container(&self, i: usize) -> bool {
        matches!(self.lines.get(i).map(|l| &l.row), Some(Row::Open { .. }))
    }

    /// Whether line `i` is a collapsed container.
    pub fn is_collapsed(&self, i: usize) -> bool {
        self.collapsed.contains(&i)
    }

    /// Toggles the container at line `i` (no-op for other lines).
    pub fn toggle(&mut self, i: usize) {
        if self.is_container(i) && !self.collapsed.remove(&i) {
            self.collapsed.insert(i);
        }
    }

    /// Sets the collapsed state of the container at line `i`.
    pub fn set_collapsed(&mut self, i: usize, collapsed: bool) {
        if self.is_container(i) {
            if collapsed {
                self.collapsed.insert(i);
            } else {
                self.collapsed.remove(&i);
            }
        }
    }

    /// The nearest container line enclosing line `i`.
    pub fn parent(&self, i: usize) -> Option<usize> {
        let depth = self.lines.get(i)?.depth;
        (0..i)
            .rev()
            .find(|&j| self.lines[j].depth + 1 == depth && self.is_container(j))
    }

    /// Collapses every container except the root.
    pub fn collapse_all(&mut self) {
        self.collapsed = (1..self.lines.len())
            .filter(|&i| self.is_container(i))
            .collect();
    }

    /// Expands everything.
    pub fn expand_all(&mut self) {
        self.collapsed.clear();
    }

    /// Plain text of line `i` as displayed (used for tests and search).
    pub fn text(&self, i: usize) -> String {
        self.spans(i)
            .iter()
            .map(|s| s.content.to_string())
            .collect()
    }

    fn spans(&self, i: usize) -> Vec<Span<'static>> {
        let l = &self.lines[i];
        let mut spans = vec![Span::raw("  ".repeat(l.depth))];
        if let Some(k) = &l.key {
            spans.push(Span::styled(
                serde_json::to_string(k).unwrap_or_default(),
                Style::default().fg(Color::Cyan),
            ));
            spans.push(Span::raw(": "));
        }
        let comma = if l.comma { "," } else { "" };
        match &l.row {
            Row::Open {
                bracket,
                len,
                close,
            } => {
                let (o, c) = bracket.chars();
                if self.collapsed.contains(&i) {
                    let unit = if *bracket == Bracket::Object {
                        "keys"
                    } else {
                        "items"
                    };
                    let trailing = if self.lines[*close].comma { "," } else { "" };
                    spans.push(Span::raw(format!("{o} ")));
                    spans.push(Span::styled(
                        format!("… {len} {unit}"),
                        Style::default().fg(Color::DarkGray),
                    ));
                    spans.push(Span::raw(format!(" {c}{trailing}")));
                } else {
                    spans.push(Span::raw(o.to_string()));
                }
            }
            Row::Close(bracket) => spans.push(Span::raw(format!("{}{comma}", bracket.chars().1))),
            Row::Leaf(v) => {
                let color = match v {
                    Value::String(_) => Color::Green,
                    Value::Number(_) => Color::Yellow,
                    Value::Bool(_) => Color::Magenta,
                    _ => Color::DarkGray,
                };
                spans.push(Span::styled(
                    serde_json::to_string(v).unwrap_or_default(),
                    Style::default().fg(color),
                ));
                spans.push(Span::raw(comma.to_string()));
            }
        }
        spans
    }
}

/// Tabs of the response viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Response body.
    Body,
    /// Response headers and timing.
    Headers,
    /// The request as sent.
    Request,
}

const TABS: [Tab; 3] = [Tab::Body, Tab::Headers, Tab::Request];

/// Result of handling a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing else to do.
    None,
    /// Leave the current screen.
    Quit,
    /// Re-run the history entry with this id.
    Rerun(i64),
}

/// Viewer for one exchange.
#[derive(Debug, Clone)]
pub struct ResponseView {
    /// Title line.
    pub title: String,
    exchange: Exchange,
    tree: Option<JsonTree>,
    text: Vec<String>,
    /// Current tab.
    pub tab: Tab,
    cursor: usize,
    scroll: usize,
}

impl ResponseView {
    /// Builds a viewer; JSON bodies become a collapsible tree.
    pub fn new(title: String, exchange: Exchange) -> ResponseView {
        let body = exchange
            .response
            .as_ref()
            .map(|r| r.body.clone())
            .unwrap_or_default();
        let tree = serde_json::from_slice::<Value>(&body)
            .ok()
            .filter(|v| v.is_object() || v.is_array())
            .map(|v| JsonTree::new(&v));
        let text = if tree.is_some() {
            vec![]
        } else {
            let kind = crate::view::body_kind(
                exchange.response.as_ref().and_then(|r| r.content_type()),
                &body,
            );
            crate::view::pretty_body(kind, &body)
                .lines()
                .map(str::to_string)
                .collect()
        };
        ResponseView {
            title,
            exchange,
            tree,
            text,
            tab: Tab::Body,
            cursor: 0,
            scroll: 0,
        }
    }

    fn row_count(&self) -> usize {
        match self.tab {
            Tab::Body => self
                .tree
                .as_ref()
                .map(|t| t.visible().len())
                .unwrap_or(self.text.len()),
            Tab::Headers => self.header_lines().len(),
            Tab::Request => self.request_lines().len(),
        }
    }

    fn header_lines(&self) -> Vec<Line<'static>> {
        let mut out = Vec::new();
        let t = &self.exchange.timing;
        out.push(Line::from(Span::styled(
            format!(
                "total {:.1} ms · first byte {:.1} ms · connect {:.1} ms",
                t.total_ms, t.ttfb_ms, t.connect_ms
            ),
            Style::default().fg(Color::DarkGray),
        )));
        if let Some(r) = &self.exchange.response {
            for (k, v) in &r.headers {
                out.push(Line::from(vec![
                    Span::styled(k.clone(), Style::default().fg(Color::Cyan)),
                    Span::raw(format!(": {v}")),
                ]));
            }
        }
        out
    }

    fn request_lines(&self) -> Vec<Line<'static>> {
        let r = &self.exchange.request;
        let mut out = vec![Line::from(Span::styled(
            format!("{} {}", r.method, r.url),
            Style::default().add_modifier(Modifier::BOLD),
        ))];
        for (k, v) in &r.headers {
            out.push(Line::from(vec![
                Span::styled(k.clone(), Style::default().fg(Color::Cyan)),
                Span::raw(format!(": {v}")),
            ]));
        }
        if !r.body.is_empty() {
            out.push(Line::raw(""));
            let kind = crate::view::body_kind(None, &r.body);
            out.extend(
                crate::view::pretty_body(kind, &r.body)
                    .lines()
                    .map(|l| Line::raw(l.to_string())),
            );
        }
        out
    }

    fn current_line(&self) -> Option<usize> {
        self.tree
            .as_ref()
            .and_then(|t| t.visible().get(self.cursor).copied())
    }

    /// Handles a key; returns whether the viewer wants to quit.
    pub fn handle(&mut self, key: KeyEvent) -> Action {
        let rows = self.row_count();
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Tab => self
                .switch((TABS.iter().position(|t| *t == self.tab).unwrap_or(0) + 1) % TABS.len()),
            KeyCode::BackTab => self.switch(
                (TABS.iter().position(|t| *t == self.tab).unwrap_or(0) + TABS.len() - 1)
                    % TABS.len(),
            ),
            KeyCode::Char(c @ '1'..='3') => self.switch(c as usize - '1' as usize),
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = (self.cursor + 1).min(rows.saturating_sub(1))
            }
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::PageDown | KeyCode::Char('d')
                if key.code == KeyCode::PageDown
                    || key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.cursor = (self.cursor + 20).min(rows.saturating_sub(1))
            }
            KeyCode::PageUp | KeyCode::Char('u')
                if key.code == KeyCode::PageUp || key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.cursor = self.cursor.saturating_sub(20)
            }
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => self.cursor = rows.saturating_sub(1),
            KeyCode::Enter | KeyCode::Char(' ') if self.tab == Tab::Body => {
                if let (Some(line), Some(t)) = (self.current_line(), self.tree.as_mut()) {
                    t.toggle(line);
                }
            }
            KeyCode::Right | KeyCode::Char('l') if self.tab == Tab::Body => {
                if let (Some(line), Some(t)) = (self.current_line(), self.tree.as_mut()) {
                    t.set_collapsed(line, false);
                }
            }
            KeyCode::Left | KeyCode::Char('h') if self.tab == Tab::Body => {
                if let (Some(line), Some(t)) = (self.current_line(), self.tree.as_mut()) {
                    if t.is_container(line) && !t.is_collapsed(line) {
                        t.set_collapsed(line, true);
                    } else if let Some(p) = t.parent(line) {
                        t.set_collapsed(p, true);
                        self.cursor = t.visible().iter().position(|&i| i == p).unwrap_or(0);
                    }
                }
            }
            KeyCode::Char('c') if self.tab == Tab::Body => {
                if let Some(t) = self.tree.as_mut() {
                    t.collapse_all();
                    self.cursor = 0;
                }
            }
            KeyCode::Char('e') if self.tab == Tab::Body => {
                if let Some(t) = self.tree.as_mut() {
                    t.expand_all();
                }
            }
            _ => {}
        }
        self.cursor = self.cursor.min(self.row_count().saturating_sub(1));
        Action::None
    }

    fn switch(&mut self, index: usize) {
        self.tab = TABS[index];
        self.cursor = 0;
        self.scroll = 0;
    }

    /// Draws the viewer into `area`.
    pub fn draw(&mut self, f: &mut Frame, area: Rect, focused: bool) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(1),
                Constraint::Min(1),
            ])
            .split(area);
        let status = match &self.exchange.response {
            Some(r) => {
                let color = if r.http_version == "gRPC" {
                    if r.status == 0 {
                        Color::Green
                    } else {
                        Color::Red
                    }
                } else if r.status < 300 {
                    Color::Green
                } else if r.status < 400 {
                    Color::Cyan
                } else if r.status < 500 {
                    Color::Yellow
                } else {
                    Color::Red
                };
                Line::from(vec![
                    Span::styled(
                        format!("{} {} {}", r.http_version, r.status, r.reason),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("  {:.1} ms  {}", self.exchange.timing.total_ms, self.title),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])
            }
            None => Line::from(Span::styled(
                format!("error: {}", self.exchange.error.clone().unwrap_or_default()),
                Style::default().fg(Color::Red),
            )),
        };
        f.render_widget(Paragraph::new(status), chunks[0]);
        let selected = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
        f.render_widget(
            Tabs::new(vec!["1 Body", "2 Headers", "3 Request"])
                .select(selected)
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
            chunks[1],
        );
        let body_area = chunks[2];
        let height = body_area.height.saturating_sub(2) as usize;
        if self.cursor < self.scroll {
            self.scroll = self.cursor;
        } else if height > 0 && self.cursor >= self.scroll + height {
            self.scroll = self.cursor + 1 - height;
        }
        let mut lines: Vec<Line> = match self.tab {
            Tab::Body => match &self.tree {
                Some(t) => t
                    .visible()
                    .into_iter()
                    .map(|i| Line::from(t.spans(i)))
                    .collect(),
                None => self.text.iter().map(|l| Line::raw(l.clone())).collect(),
            },
            Tab::Headers => self.header_lines(),
            Tab::Request => self.request_lines(),
        };
        if let Some(l) = lines.get_mut(self.cursor) {
            *l = l.clone().style(Style::default().bg(Color::DarkGray));
        }
        let visible: Vec<Line> = lines
            .into_iter()
            .skip(self.scroll)
            .take(height.max(1))
            .collect();
        let border = if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        f.render_widget(
            Paragraph::new(visible)
                .block(Block::default().borders(Borders::ALL).border_style(border)),
            body_area,
        );
    }
}

/// History browser: entry list plus a viewer of the selected entry.
pub struct HistoryApp {
    entries: Vec<Entry>,
    list: ListState,
    filter: String,
    filtering: bool,
    detail_focus: bool,
    view: Option<ResponseView>,
    /// Status-bar message.
    pub message: String,
}

impl HistoryApp {
    /// Creates the browser for `entries` (newest first).
    pub fn new(entries: Vec<Entry>) -> HistoryApp {
        let mut app = HistoryApp {
            entries,
            list: ListState::default(),
            filter: String::new(),
            filtering: false,
            detail_focus: false,
            view: None,
            message: String::new(),
        };
        app.list.select(Some(0));
        app.load_view();
        app
    }

    /// Replaces the entries (after a re-run), keeping the filter.
    pub fn reload(&mut self, entries: Vec<Entry>) {
        self.entries = entries;
        self.list.select(Some(0));
        self.load_view();
    }

    fn matches(&self) -> Vec<usize> {
        let f = self.filter.to_ascii_lowercase();
        (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                f.is_empty() || Self::label(e).to_ascii_lowercase().contains(&f)
            })
            .collect()
    }

    fn label(e: &Entry) -> String {
        let status = e
            .exchange
            .response
            .as_ref()
            .map(|r| r.status.to_string())
            .unwrap_or_else(|| "ERR".into());
        format!(
            "#{:<4} {:<6} {:<4} {}",
            e.id,
            e.exchange.request.method,
            status,
            e.file
                .clone()
                .unwrap_or_else(|| e.exchange.request.url.clone())
        )
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let m = self.matches();
        self.list
            .selected()
            .and_then(|i| m.get(i))
            .map(|&i| &self.entries[i])
    }

    fn load_view(&mut self) {
        self.view = self.selected_entry().map(|e| {
            ResponseView::new(
                format!(
                    "#{} {}",
                    e.id,
                    e.ts.with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M:%S")
                ),
                e.exchange.clone(),
            )
        });
    }

    /// Handles a key.
    pub fn handle(&mut self, key: KeyEvent) -> Action {
        if self.filtering {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                }
                KeyCode::Char(c) => self.filter.push(c),
                _ => {}
            }
            self.list.select(Some(0));
            self.load_view();
            return Action::None;
        }
        if self.detail_focus {
            if let Some(v) = self.view.as_mut()
                && v.handle(key) == Action::Quit
            {
                self.detail_focus = false;
            }
            return Action::None;
        }
        let n = self.matches().len();
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Down | KeyCode::Char('j') => self.list.select(Some(
                (self.list.selected().unwrap_or(0) + 1).min(n.saturating_sub(1)),
            )),
            KeyCode::Up | KeyCode::Char('k') => self
                .list
                .select(Some(self.list.selected().unwrap_or(0).saturating_sub(1))),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if self.view.is_some() => {
                self.detail_focus = true;
                return Action::None;
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                return Action::None;
            }
            KeyCode::Char('r') => {
                if let Some(e) = self.selected_entry() {
                    return Action::Rerun(e.id);
                }
            }
            _ => return Action::None,
        }
        self.load_view();
        Action::None
    }

    /// Draws the browser.
    pub fn draw(&mut self, f: &mut Frame) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(f.area());
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(rows[0]);
        let items: Vec<ListItem> = self
            .matches()
            .into_iter()
            .map(|i| {
                let e = &self.entries[i];
                let ok = e.exchange.response.as_ref().is_some_and(|r| {
                    if r.http_version == "gRPC" {
                        r.status == 0
                    } else {
                        r.status < 400
                    }
                });
                ListItem::new(Self::label(e)).style(Style::default().fg(if ok {
                    Color::Reset
                } else {
                    Color::Red
                }))
            })
            .collect();
        let title = if self.filter.is_empty() && !self.filtering {
            " history ".to_string()
        } else {
            format!(
                " filter: {}{} ",
                self.filter,
                if self.filtering { "▏" } else { "" }
            )
        };
        let border = if self.detail_focus {
            Style::default()
        } else {
            Style::default().fg(Color::Cyan)
        };
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(border),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(list, cols[0], &mut self.list);
        match self.view.as_mut() {
            Some(v) => v.draw(f, cols[1], self.detail_focus),
            None => f.render_widget(
                Paragraph::new("no history entries").block(Block::default().borders(Borders::ALL)),
                cols[1],
            ),
        }
        let help = if self.detail_focus {
            "j/k move · enter/space fold · h/l collapse/expand · c/e all · tab switch · esc back"
        } else {
            "j/k select · enter open · / filter · r re-run · q quit"
        };
        let bar = if self.message.is_empty() {
            help.to_string()
        } else {
            format!("{} · {help}", self.message)
        };
        f.render_widget(
            Paragraph::new(Span::styled(bar, Style::default().fg(Color::DarkGray))),
            rows[1],
        );
    }
}

/// Fails unless stdin and stdout are terminals.
pub fn require_terminal() -> Result<()> {
    if !(std::io::stdout().is_terminal() && std::io::stdin().is_terminal()) {
        bail!("the TUI needs an interactive terminal; drop --tui (or use --plain) for text output");
    }
    Ok(())
}

/// Next key press (ignoring key releases and other events).
fn next_key() -> Result<KeyEvent> {
    loop {
        if let Event::Key(k) = event::read()?
            && k.kind == KeyEventKind::Press
        {
            return Ok(k);
        }
    }
}

/// Shows one exchange until the user quits.
pub fn view_exchange(title: String, exchange: Exchange) -> Result<()> {
    require_terminal()?;
    let mut view = ResponseView::new(title, exchange);
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|f| {
                let area = f.area();
                let rows = Layout::default().direction(Direction::Vertical).constraints([Constraint::Min(3), Constraint::Length(1)]).split(area);
                view.draw(f, rows[0], true);
                f.render_widget(Paragraph::new(Span::styled("j/k move · enter/space fold · h/l collapse/expand · c/e all · tab switch · q quit", Style::default().fg(Color::DarkGray))), rows[1]);
            })?;
            if view.handle(next_key()?) == Action::Quit {
                return Ok(());
            }
        }
    })();
    ratatui::restore();
    result
}

/// Runs the history browser. `rerun` re-runs an entry and returns a status
/// message; `load` reloads the entries.
pub fn browse_history(
    entries: Vec<Entry>,
    rerun: &mut dyn FnMut(i64) -> Result<String>,
    load: &mut dyn FnMut() -> Result<Vec<Entry>>,
) -> Result<()> {
    require_terminal()?;
    let mut app = HistoryApp::new(entries);
    let mut terminal = ratatui::init();
    let result = (|| -> Result<()> {
        loop {
            terminal.draw(|f| app.draw(f))?;
            match app.handle(next_key()?) {
                Action::Quit => return Ok(()),
                Action::Rerun(id) => {
                    app.message = match rerun(id) {
                        Ok(m) => m,
                        Err(e) => format!("re-run failed: {e:#}"),
                    };
                    app.reload(load()?);
                }
                Action::None => {}
            }
        }
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curlexec::{RequestRecord, ResponseRecord, Timing};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use serde_json::json;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn sample() -> Value {
        json!({"id": 1, "tags": ["a", "b"], "nested": {"ok": true, "n": null}})
    }

    fn exchange(body: &Value) -> Exchange {
        Exchange {
            request: RequestRecord {
                method: "GET".into(),
                url: "http://h/x".into(),
                headers: vec![("Accept".into(), "*/*".into())],
                body: vec![],
            },
            response: Some(ResponseRecord {
                status: 200,
                http_version: "HTTP/1.1".into(),
                reason: "OK".into(),
                headers: vec![("content-type".into(), "application/json".into())],
                size: 0,
                body: serde_json::to_vec(body).unwrap(),
            }),
            timing: Timing {
                total_ms: 3.0,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn tree_folds_and_unfolds() {
        let mut t = JsonTree::new(&sample());
        let texts = |t: &JsonTree| {
            t.visible()
                .into_iter()
                .map(|i| t.text(i))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            texts(&t),
            vec![
                "{",
                "  \"id\": 1,",
                "  \"tags\": [",
                "    \"a\",",
                "    \"b\"",
                "  ],",
                "  \"nested\": {",
                "    \"ok\": true,",
                "    \"n\": null",
                "  }",
                "}"
            ]
        );
        t.toggle(2);
        assert_eq!(texts(&t)[2], "  \"tags\": [ … 2 items ],");
        assert_eq!(t.visible().len(), 8);
        t.collapse_all();
        assert_eq!(
            texts(&t),
            vec![
                "{",
                "  \"id\": 1,",
                "  \"tags\": [ … 2 items ],",
                "  \"nested\": { … 2 keys }",
                "}"
            ]
        );
        t.expand_all();
        assert_eq!(t.visible().len(), 11);
        assert_eq!(t.parent(3), Some(2));
        t.toggle(1);
        assert!(!t.is_collapsed(1), "scalars cannot fold");
    }

    #[test]
    fn viewer_keys_and_rendering() {
        let mut v = ResponseView::new("#1".into(), exchange(&sample()));
        v.handle(key(KeyCode::Char('j')));
        v.handle(key(KeyCode::Char('j')));
        v.handle(key(KeyCode::Enter));
        assert_eq!(
            v.tree.as_ref().unwrap().visible().len(),
            8,
            "enter folds the array under the cursor"
        );
        v.handle(key(KeyCode::Char('j')));
        v.handle(key(KeyCode::Left));
        assert_eq!(
            v.tree.as_ref().unwrap().visible().len(),
            5,
            "left on an open container collapses it"
        );
        v.handle(key(KeyCode::Left));
        assert_eq!(
            v.tree.as_ref().unwrap().visible().len(),
            1,
            "left on a collapsed child collapses its parent (the root)"
        );
        v.handle(key(KeyCode::Char('e')));
        v.handle(key(KeyCode::Tab));
        assert_eq!(v.tab, Tab::Headers);
        let mut term = Terminal::new(TestBackend::new(70, 12)).unwrap();
        term.draw(|f| v.draw(f, f.area(), true)).unwrap();
        let screen = format!("{:?}", term.backend().buffer());
        assert!(
            screen.contains("HTTP/1.1 200 OK")
                && screen.contains("content-type: application/json")
                && screen.contains("2 Headers"),
            "{screen}"
        );
        assert_eq!(v.handle(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn history_browser_filters_and_reruns() {
        let entry = |id: i64, file: &str| Entry {
            id,
            ts: chrono::Utc::now(),
            file: Some(file.into()),
            env: None,
            vars: Default::default(),
            file_sha256: None,
            redacted: true,
            body_truncated: false,
            exchange: exchange(&json!({"file": file})),
            request_body: String::new(),
            response_body: String::new(),
        };
        let mut app = HistoryApp::new(vec![
            entry(2, "users/get-user.curl"),
            entry(1, "auth/login.curl"),
        ]);
        app.handle(key(KeyCode::Char('/')));
        for c in "login".chars() {
            app.handle(key(KeyCode::Char(c)));
        }
        app.handle(key(KeyCode::Enter));
        assert_eq!(app.handle(key(KeyCode::Char('r'))), Action::Rerun(1));
        let mut term = Terminal::new(TestBackend::new(100, 14)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        let screen = format!("{:?}", term.backend().buffer());
        assert!(
            screen.contains("filter: login")
                && screen.contains("auth/login.curl")
                && !screen.contains("users/get-user.curl"),
            "{screen}"
        );
        assert!(screen.contains("\"file\": \"auth/login.curl\""), "{screen}");
        app.handle(key(KeyCode::Enter));
        assert_eq!(
            app.handle(key(KeyCode::Char('q'))),
            Action::None,
            "q in the detail pane returns to the list"
        );
        assert_eq!(app.handle(key(KeyCode::Char('q'))), Action::Quit);
    }
}
