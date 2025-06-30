use std::{io, time::Duration};

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
use tui_logger::{TuiLoggerLevelOutput, TuiLoggerWidget};

#[derive(Debug)]
pub(super) struct App {
    title: String,
    screen: Screen,
    fatal_error: Option<OpaqueError>,

    input_buffer: String,
    history: ChatHistory,

    socket: ClientWebSocket,

    terminal: Terminal<CrosstermBackend<io::Stdout>>,
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
}

impl ChatMessage {
    fn new_client(message: Utf8Bytes) -> Self {
        Self {
            role: Role::Client,
            message,
        }
    }

    fn new_server(message: Utf8Bytes) -> Self {
        Self {
            role: Role::Server,
            message,
        }
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
        let log_file_path = super::log::init_logger(cfg.clone()).context("init tui logger")?;

        let socket = super::client::connect(cfg.clone())
            .await
            .context("create websocket stream")?;
        let terminal = ratatui::init();

        Ok(App {
            title: format!(
                "  rama-ws @ {} | logs: {} ",
                cfg.uri,
                log_file_path.to_string_lossy()
            ),
            screen: Screen::Chat(ChatMode::Insert),
            fatal_error: None,
            input_buffer: Default::default(),
            history: ChatHistory::default(),
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
                        if self.fatal_error.is_some() {
                            "  chat | 'q' quit | 't' logs view  "
                        } else {
                            "  chat | 'q' quit | 'i' insert | 't' logs view  "
                        }
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

                    Paragraph::new(match self.fatal_error.as_ref() {
                        Some(err) => format!(" Fatal Error (please exit): {err} "),
                        None => format!(
                            " > {}{}",
                            self.input_buffer,
                            match mode {
                                ChatMode::Insert => "_ ",
                                ChatMode::View => " ",
                            }
                        ),
                    })
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
                    let logs = TuiLoggerWidget::default()
                        .block(main_block)
                        .style_error(Style::default().fg(Color::Red))
                        .style_debug(Style::default().fg(Color::Green))
                        .style_warn(Style::default().fg(Color::Yellow))
                        .style_trace(Style::default().fg(Color::Magenta))
                        .style_info(Style::default().fg(Color::Cyan))
                        .output_level(Some(TuiLoggerLevelOutput::Abbreviated));

                    frame.render_widget(logs, frame.area());
                }
            })
            .context("draw tui screen")?;
        Ok(())
    }

    async fn update(&mut self) -> Result<bool, OpaqueError> {
        while let Some(result) = self.socket.next().now_or_never().unwrap_or_default() {
            match result {
                Ok(Message::Text(text)) => {
                    self.history.items.push(ChatMessage::new_server(text));
                    self.history.state.select_last();
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
                    Screen::Chat(ChatMode::Insert) => {
                        if self.fatal_error.is_some() {
                            self.screen = Screen::Chat(ChatMode::View);
                            return Ok(false);
                        }

                        match key.code {
                            KeyCode::Esc => {
                                self.screen = Screen::Chat(ChatMode::View);
                            }
                            KeyCode::Enter if !self.input_buffer.is_empty() => {
                                let message = std::mem::take(&mut self.input_buffer);
                                self.socket
                                    .send_message(message.clone().into())
                                    .await
                                    .context("send WS message")?;
                                self.history
                                    .items
                                    .push(ChatMessage::new_client(Utf8Bytes::from(message)));
                                self.history.state.select_last();
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
                        }
                    }
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
    }
}

impl From<&ChatMessage> for ListItem<'_> {
    fn from(value: &ChatMessage) -> Self {
        let line = Line::from(format!(
            " {} {} ",
            match value.role {
                Role::Server => "<<",
                Role::Client => ">>",
            },
            value.message
        ));
        ListItem::new(line)
    }
}
