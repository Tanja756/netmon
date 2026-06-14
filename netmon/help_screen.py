from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Static


class HelpScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Container(
            Static(
                """
╔══════════════════════════════════════════════════════════════════╗
║                        ГОРЯЧИЕ КЛАВИШИ                           ║
╠══════════════════════════════════════════════════════════════════╣
║  ↑ / ↓         – навигация по таблице                           ║
║  Enter         – выбрать сервер, показать клиентов              ║
║  /             – поиск (фильтр)                                 ║
║  ESC           – сбросить поиск                                 ║
║  Пробел        – пауза / возобновление автообновления           ║
║  S             – показать / скрыть таблицу клиентов             ║
║  Q             – выход                                          ║
║  ?             – эта справка                                    ║
╚══════════════════════════════════════════════════════════════════╝
                """,
                id="help-text",
            ),
            id="help-container",
        )

    def on_key(self, event) -> None:
        self.app.pop_screen()