use std::{fmt, io, path::PathBuf, time::Duration};

use chrono::{DateTime, Local};
use rama::{
    error::{ErrorContext, ErrorExt, OpaqueError},
    futures::{FutureExt, StreamExt},
    graceful::ShutdownGuard,
    http::ws::{Message, Utf8Bytes, handshake::client::ClientWebSocket, protocol::Role},
    telemetry::tracing,
};
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    prelude::*,
    widgets::{Block, HighlightSpacing, List, ListItem, ListState, Paragraph},
};
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerSmartWidget, TuiWidgetState};

pub(super) struct App {
    title: String,
    log_file_path: PathBuf,

    screen: Screen,

    input_buffer: String,
    history: ChatHistory,

    tui_logger_state: TuiWidgetState,

    socket: ClientWebSocket,

    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl fmt::Debug for App {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("App")
            .field("title", &self.title)
            .field("screen", &self.screen)
            .field("input_buffer", &self.input_buffer)
            .field("history", &self.history)
            .field("tui_logger_state", &())
            .field("socket", &self.socket)
            .field("terminal", &self.terminal)
            .finish()
    }
}

#[derive(Debug, Default)]
struct ChatHistory {
    items: Vec<ChatMessage>,
    state: ListState,
}

#[derive(Debug)]
struct ChatMessage {
    role: Role,
    message: Utf8Bytes,
    ts: DateTime<Local>,
}

impl ChatHistory {
    fn push_client_message(&mut self, message: Utf8Bytes) {
        let msg = ChatMessage {
            role: Role::Client,
            message,
            ts: Local::now(),
        };
        self.items.push(msg);
        self.state.select_last();
    }

    fn push_server_message(&mut self, message: Utf8Bytes) {
        let msg = ChatMessage {
            role: Role::Server,
            message,
            ts: Local::now(),
        };
        self.items.push(msg);
        self.state.select_last();
    }
}

#[derive(Debug)]
enum Screen {
    Chat(ChatMode),
    Logs,
}

#[derive(Debug)]
enum ChatMode {
    Insert,
    View,
}

impl App {
    pub(super) async fn new(cfg: super::CliCommandWs) -> Result<Self, OpaqueError> {
        let log_file_path = super::log::init_logger().context("init tui logger")?;

        let socket = super::client::connect(cfg.clone())
            .await
            .context("create websocket stream")?;
        let terminal = ratatui::init();

        Ok(Self {
            title: format!(
                "  rama-ws @ {} | logs: {} ",
                cfg.uri,
                log_file_path.to_string_lossy()
            ),
            log_file_path,
            screen: Screen::Chat(ChatMode::Insert),
            input_buffer: Default::default(),
            history: ChatHistory::default(),
            tui_logger_state: TuiWidgetState::new(),
            socket,
            terminal,
        })
    }

    pub(super) async fn run(&mut self, guard: ShutdownGuard) -> Result<(), OpaqueError> {
        loop {
            self.render()?;

            if guard
                .cancelled()
                .now_or_never()
                .map(|_| true)
                .unwrap_or_default()
            {
                tracing::info!("guard cancelled: exit tui");
                return Ok(());
            }

            if self.update().await? {
                tracing::info!("user quit: exit tui");
                return Ok(());
            }

            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn render(&mut self) -> Result<(), OpaqueError> {
        let main_block =
            Block::bordered()
                .title(self.title.as_str())
                .title_bottom(match self.screen {
                    Screen::Chat(ChatMode::Insert) => {
                        "  chat | type input | 'esc' exit insert mode  "
                    }
                    Screen::Chat(ChatMode::View) => {
                        "  chat | 'q' quit | 'i' insert | 't' logs view  "
                    }
                    Screen::Logs => "  logs | q' quit | 'esc' chat view  ",
                });

        self.terminal
            .draw(|frame: &mut Frame| match &self.screen {
                Screen::Chat(mode) => {
                    let [title, _, history, _, input] = Layout::vertical([
                        Constraint::Length(2), // title
                        Constraint::Length(1), // gap
                        Constraint::Fill(1),   // history
                        Constraint::Length(1), // gap
                        Constraint::Length(3), // input
                    ])
                    .areas(frame.area());

                    main_block.render(title, frame.buffer_mut());

                    Paragraph::new(format!(
                        " > {}{}",
                        self.input_buffer,
                        match mode {
                            ChatMode::Insert => "_ ",
                            ChatMode::View => " ",
                        }
                    ))
                    .block(Block::bordered())
                    .render(input, frame.buffer_mut());

                    let items: Vec<ListItem> = self.history.items.iter().map(Into::into).collect();
                    let list = List::new(items).highlight_spacing(HighlightSpacing::Always);
                    StatefulWidget::render(
                        list,
                        history,
                        frame.buffer_mut(),
                        &mut self.history.state,
                    );
                }
                Screen::Logs => {
                    let [title, logger] = Layout::vertical([
                        Constraint::Length(3), // title
                        Constraint::Fill(1),   // logger
                    ])
                    .areas(frame.area());

                    let logs = TuiLoggerSmartWidget::default()
                        .state(&self.tui_logger_state)
                        .style_error(Style::default().fg(Color::Red))
                        .style_debug(Style::default().fg(Color::Green))
                        .style_warn(Style::default().fg(Color::Yellow))
                        .style_trace(Style::default().fg(Color::Gray))
                        .style_info(Style::default().fg(Color::Cyan))
                        .output_level(Some(TuiLoggerLevelOutput::Abbreviated));

                    let instructions = Paragraph::new(
                        "  'h' visible | 'f' focus | '↔' level select | '↕' target select | '+/-' capture level | 'j/k' scroll | 's' scroll mode | 't' target toggle  "
                    ).block(main_block);
                    instructions.render(title, frame.buffer_mut());

                    logs.render(logger, frame.buffer_mut());
                }
            })
            .context("draw tui screen")?;
        Ok(())
    }

    async fn update(&mut self) -> Result<bool, OpaqueError> {
        while let Some(result) = self.socket.next().now_or_never().unwrap_or_default() {
            match result {
                Ok(Message::Text(text)) => {
                    self.history.push_server_message(text);
                }
                Ok(message) => {
                    tracing::info!("received non-text message: {message}");
                }
                Err(err) => {
                    return Err(err.context("failure while trying to receive next ws message"));
                }
            }
        }

        if event::poll(Duration::from_millis(250)).context("event poll failed")? {
            if let Event::Key(key) = event::read().context("event read failed")? {
                if key.kind != KeyEventKind::Press {
                    return Ok(false);
                }

                match self.screen {
                    Screen::Chat(ChatMode::Insert) => match key.code {
                        KeyCode::Esc => {
                            self.screen = Screen::Chat(ChatMode::View);
                        }
                        KeyCode::Enter if !self.input_buffer.is_empty() => {
                            let message = std::mem::take(&mut self.input_buffer);
                            self.socket
                                .send_message(message.clone().into())
                                .await
                                .context("send WS message")?;
                            self.history.push_client_message(Utf8Bytes::from(message));
                        }
                        KeyCode::Backspace => {
                            if let Some(char) = self.input_buffer.pop() {
                                tracing::debug!("popped character from input buffer: {char}");
                            }
                        }
                        KeyCode::Char(char) if char.is_ascii() => {
                            self.input_buffer.push(char);
                        }
                        _ => (),
                    },
                    Screen::Chat(ChatMode::View) => match key.code {
                        KeyCode::Char('q') => return Ok(true),
                        KeyCode::Char('i') => {
                            self.screen = Screen::Chat(ChatMode::Insert);
                        }
                        KeyCode::Char('t') => {
                            self.screen = Screen::Logs;
                        }
                        _ => (),
                    },
                    Screen::Logs => match key.code {
                        KeyCode::Char('q') => return Ok(true),
                        KeyCode::Esc => {
                            self.screen = Screen::Chat(ChatMode::View);
                        }
                        KeyCode::Char('h') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::HideKey);
                        }
                        KeyCode::Char('f') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::FocusKey);
                        }
                        KeyCode::Up => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::UpKey);
                        }
                        KeyCode::Down => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::DownKey);
                        }
                        KeyCode::Left => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::LeftKey);
                        }
                        KeyCode::Right => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::RightKey);
                        }
                        KeyCode::Char('-') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::MinusKey);
                        }
                        KeyCode::Char('+') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::PlusKey);
                        }
                        KeyCode::Char('k') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::PrevPageKey);
                        }
                        KeyCode::Char('j') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::NextPageKey);
                        }
                        KeyCode::Char('s') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::EscapeKey);
                        }
                        KeyCode::Char('t') => {
                            self.tui_logger_state
                                .transition(tui_logger::TuiWidgetEvent::SpaceKey);
                        }
                        _ => (),
                    },
                }
            }
        }
        Ok(false)
    }
}

impl Drop for App {
    fn drop(&mut self) {
        ratatui::restore();
        eprintln!(
            "Bye! Logfile available at {}",
            self.log_file_path.to_string_lossy()
        )
    }
}

impl From<&ChatMessage> for ListItem<'_> {
    fn from(value: &ChatMessage) -> Self {
        let line = Line::from(format!(
            "[{}] {} {} ",
            value.ts.time(),
            match value.role {
                Role::Server => "<<",
                Role::Client => ">>",
            },
            value.message
        ));
        ListItem::new(line)
    }
}
