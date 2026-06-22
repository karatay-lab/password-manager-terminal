use color_eyre::Result;

use pwd_manager_terminal::app::App;
use pwd_manager_terminal::config::Config;

fn main() -> Result<()> {
    // Install color-eyre first so ratatui's panic hook wraps it: on a panic the
    // terminal is restored *before* the report is printed.
    color_eyre::install()?;

    // Merge .env layers (cwd, ~/.config, /etc) into the environment; all are
    // optional. Lets a globally installed binary find config outside its cwd.
    pwd_manager_terminal::config::load_env_files();
    let config = Config::from_env();

    // Build the app (HTTP client, runtime, store) before entering raw mode so an
    // early failure prints normally instead of on a half-initialized terminal.
    let app = App::new(config)?;

    let terminal = ratatui::init();
    let result = app.run(terminal);
    ratatui::restore();
    result
}
