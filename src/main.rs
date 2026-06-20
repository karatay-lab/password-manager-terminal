use color_eyre::Result;

use pwd_manager_terminal::app::App;
use pwd_manager_terminal::config::Config;

fn main() -> Result<()> {
    // Install color-eyre first so ratatui's panic hook wraps it: on a panic the
    // terminal is restored *before* the report is printed.
    color_eyre::install()?;

    // Load .env if present; missing file is fine (env vars may be set another way).
    let _ = dotenvy::dotenv();
    let config = Config::from_env();

    let terminal = ratatui::init();
    let result = App::new(config).run(terminal);
    ratatui::restore();
    result
}
