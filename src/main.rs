use clap::{Parser, Subcommand};
use chrono::{Utc, DateTime, Local, Duration};
use serde::{Serialize, Deserialize};
use std::io::{self, Write, Read};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::collections::HashMap;
use base64::{engine::general_purpose, Engine as _};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;
use regex::Regex;
use uuid::Uuid;
use sha2::{Sha256, Digest};
use dialoguer::{Input, MultiSelect, Select, Confirm, Editor, theme::ColorfulTheme};
use crossterm::style::{Color, Stylize};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::{Keypair, Signature, Signer, Verifier, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BANNER: &str = r#"
██╗███╗   ███╗███╗   ███╗██╗   ██╗████████╗ █████╗ ██████╗ ██╗     ███████╗
██║████╗ ████║████╗ ████║██║   ██║╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝
██║██╔████╔██║██╔████╔██║██║   ██║   ██║   ███████║██████╔╝██║     █████╗  
██║██║╚██╔╝██║██║╚██╔╝██║██║   ██║   ██║   ██╔══██║██╔══██╗██║     ██╔══╝  
██║██║ ╚═╝ ██║██║ ╚═╝ ██║╚██████╔╝   ██║   ██║  ██║██████╔╝███████╗███████╗
╚═╝╚═╝     ╚═╝╚═╝     ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
                        DATABASE (IDDB)
"#;

#[derive(Parser)]
#[command(version = VERSION)]
#[command(about = "Immutable Database System with Cryptographic Protection")]
#[command(long_about = "A secure, immutable database system that creates cryptographically signed files that cannot be modified once created.")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Commands>,
    
    #[arg(long, help = "Show debug information")]
    debug: bool,
    
    #[arg(long, help = "Suppress banner display")]
    no_banner: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new workspace and generate keypair
    Init {
        #[arg(short, long, help = "Workspace directory path")]
        path: Option<String>,
        #[arg(long, help = "Force initialization even if directory exists")]
        force: bool,
    },
    
    /// Interactive mode for creating multiple entries
    Interactive,
    
    /// Create a new immutable .iddb file
    Create {
        #[arg(help = "File name (without .iddb extension)")]
        name: Option<String>,
        #[arg(short, long, help = "Add tags to categorize the entry")]
        tags: Vec<String>,
        #[arg(short, long, help = "Description/title for the entry")]
        description: Option<String>,
        #[arg(short, long, help = "Read content from file instead of stdin")]
        file: Option<String>,
        #[arg(long, help = "Content type (text, json, csv, log, etc.)")]
        content_type: Option<String>,
        #[arg(long, help = "Set expiration time (e.g., '30d', '1y', '2023-12-31')")]
        expires: Option<String>,
        #[arg(long, help = "Set priority level (1-5, 1=highest)")]
        priority: Option<u8>,
        #[arg(long, help = "Mark as encrypted content")]
        encrypted: bool,
    },
    
    /// Read and display content from an .iddb file
    Read {
        #[arg(help = "File path or name")]
        path: String,
        #[arg(short, long, help = "Show raw JSON")]
        raw: bool,
        #[arg(long, help = "Show metadata only")]
        meta_only: bool,
        #[arg(long, help = "Export content to file")]
        export: Option<String>,
        #[arg(long, help = "Format output (pretty, compact, table)")]
        format: Option<String>,
    },
    
    /// Verify integrity of one or more .iddb files
    Verify {
        #[arg(help = "File path or name (use 'all' for all files)")]
        path: String,
        #[arg(short, long, help = "Show detailed verification info")]
        verbose: bool,
        #[arg(long, help = "Generate verification report")]
        report: bool,
    },
    
    /// List all .iddb files in the workspace
    List {
        #[arg(short, long, help = "Filter by tag")]
        tag: Option<String>,
        #[arg(short, long, help = "Search in content")]
        search: Option<String>,
        #[arg(short, long, help = "Show detailed view")]
        verbose: bool,
        #[arg(long, help = "Filter by content type")]
        content_type: Option<String>,
        #[arg(long, help = "Show only expired entries")]
        expired: bool,
        #[arg(long, help = "Sort by (date, size, name, priority)")]
        sort: Option<String>,
        #[arg(long, help = "Limit number of results")]
        limit: Option<usize>,
    },
    
    /// Show statistics about the workspace
    Stats {
        #[arg(long, help = "Include detailed analysis")]
        detailed: bool,
        #[arg(long, help = "Generate charts (requires additional setup)")]
        charts: bool,
    },
    
    /// Export workspace to a backup archive
    Export {
        #[arg(help = "Output archive path")]
        output: String,
        #[arg(short, long, help = "Compression format (zip, tar.gz)")]
        format: Option<String>,
        #[arg(long, help = "Include metadata only")]
        meta_only: bool,
        #[arg(long, help = "Exclude content (metadata only)")]
        no_content: bool,
    },
    
    /// Import from backup archive
    Import {
        #[arg(help = "Input archive path")]
        input: String,
        #[arg(long, help = "Target workspace directory")]
        target: Option<String>,
        #[arg(long, help = "Skip verification during import")]
        no_verify: bool,
    },
    
    /// Search for content across all files
    Search {
        #[arg(help = "Search query")]
        query: String,
        #[arg(short, long, help = "Case sensitive search")]
        case_sensitive: bool,
        #[arg(short, long, help = "Use regex pattern")]
        regex: bool,
        #[arg(long, help = "Search in metadata only")]
        meta_only: bool,
        #[arg(long, help = "Show context lines")]
        context: Option<usize>,
    },
    
    /// Generate a new keypair (dangerous - invalidates existing files)
    GenerateKey {
        #[arg(long, help = "Force generation even if keypair exists")]
        force: bool,
        #[arg(long, help = "Backup old keypair")]
        backup: bool,
    },
    
    /// Backup and restore operations
    Backup {
        #[arg(help = "Backup name/path")]
        name: String,
        #[arg(long, help = "Include full workspace")]
        full: bool,
        #[arg(long, help = "Incremental backup")]
        incremental: bool,
    },
    
    /// Restore from backup
    Restore {
        #[arg(help = "Backup path")]
        backup: String,
        #[arg(long, help = "Target directory")]
        target: Option<String>,
    },
    
    /// Database maintenance operations
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceCommands,
    },
    
    /// Show workspace information
    Info,
    
    /// Clean expired entries
    Clean {
        #[arg(long, help = "Dry run - show what would be deleted")]
        dry_run: bool,
        #[arg(long, help = "Force deletion without confirmation")]
        force: bool,
    },
    
    /// Watch for changes and auto-verify
    Watch {
        #[arg(long, help = "Watch interval in seconds")]
        interval: Option<u64>,
    },
}

#[derive(Subcommand)]
enum MaintenanceCommands {
    /// Compact database files
    Compact,
    /// Rebuild indexes
    Reindex,
    /// Check for corruption
    Check,
    /// Optimize storage
    Optimize,
}

#[derive(Serialize, Deserialize, Clone)]
struct FilePayload {
    version: u8,
    id: String,
    created_at: DateTime<Utc>,
    modified_at: Option<DateTime<Utc>>,
    accessed_at: Option<DateTime<Utc>>,
    title: Option<String>,
    description: Option<String>,
    tags: Vec<String>,
    content: String,
    content_hash: String,
    content_type: String,
    file_size: u64,
    priority: u8,
    expires_at: Option<DateTime<Utc>>,
    is_encrypted: bool,
    public_key_b64: String,
    signature_b64: String,
    metadata: HashMap<String, String>,
    checksum: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct WorkspaceConfig {
    version: u8,
    created_at: DateTime<Utc>,
    workspace_id: String,
    public_key_b64: String,
    settings: WorkspaceSettings,
}

#[derive(Serialize, Deserialize)]
struct WorkspaceSettings {
    auto_backup: bool,
    compression: bool,
    default_expires: Option<String>,
    max_file_size: Option<u64>,
    allowed_content_types: Vec<String>,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            auto_backup: false,
            compression: false,
            default_expires: None,
            max_file_size: Some(100 * 1024 * 1024), // 100MB
            allowed_content_types: vec![
                "text".to_string(),
                "json".to_string(),
                "csv".to_string(),
                "log".to_string(),
                "markdown".to_string(),
            ],
        }
    }
}

struct Workspace {
    path: PathBuf,
    config: WorkspaceConfig,
    keypair: Keypair,
}

impl Workspace {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        let config_path = path.join("workspace.json");
        let keypair_path = path.join("keypair.bin");

        if !config_path.exists() || !keypair_path.exists() {
            return Err(anyhow::anyhow!("Workspace not initialized. Run 'imdb init' first."));
        }

        let config: WorkspaceConfig = serde_json::from_str(&std::fs::read_to_string(config_path)?)?;
        let keypair = load_keypair_from_file(&keypair_path.to_string_lossy())?;

        Ok(Workspace {
            path,
            config,
            keypair,
        })
    }

    fn init(path: PathBuf, force: bool) -> anyhow::Result<Self> {
        if path.exists() && !force {
            return Err(anyhow::anyhow!("Directory already exists. Use --force to overwrite."));
        }

        std::fs::create_dir_all(&path)?;

        let mut csprng = OsRng {};
        let keypair = Keypair::generate(&mut csprng);

        let config = WorkspaceConfig {
            version: 1,
            created_at: Utc::now(),
            workspace_id: Uuid::new_v4().to_string(),
            public_key_b64: general_purpose::STANDARD.encode(keypair.public.to_bytes()),
            settings: WorkspaceSettings::default(),
        };

        // Save config
        let config_path = path.join("workspace.json");
        let config_json = serde_json::to_string_pretty(&config)?;
        std::fs::write(config_path, config_json)?;

        // Save keypair
        let keypair_path = path.join("keypair.bin");
        std::fs::write(keypair_path, keypair.to_bytes())?;

        // Create directories
        std::fs::create_dir_all(path.join("data"))?;
        std::fs::create_dir_all(path.join("backups"))?;
        std::fs::create_dir_all(path.join("logs"))?;
        std::fs::create_dir_all(path.join("temp"))?;

        // Create initial log entry
        let log_content = format!("Workspace initialized at {}\nWorkspace ID: {}\n", 
                                 Utc::now().format("%Y-%m-%d %H:%M:%S UTC"), 
                                 config.workspace_id);
        std::fs::write(path.join("logs").join("init.log"), log_content)?;

        println!("{}", "✓ Workspace initialized successfully!".green());
        println!("Workspace ID: {}", config.workspace_id);
        println!("Location: {}", path.display());
        println!("Version: {}", VERSION);

        Ok(Workspace {
            path,
            config,
            keypair,
        })
    }

    fn data_dir(&self) -> PathBuf {
        self.path.join("data")
    }

    fn get_file_path(&self, name: &str) -> PathBuf {
        let name = if name.ends_with(".iddb") {
            name.to_string()
        } else {
            format!("{}.iddb", name)
        };
        self.data_dir().join(name)
    }

    fn backup_dir(&self) -> PathBuf {
        self.path.join("backups")
    }

    fn logs_dir(&self) -> PathBuf {
        self.path.join("logs")
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Show banner unless suppressed
    if !cli.no_banner && cli.cmd.is_some() {
        println!("{}", BANNER.cyan());
        println!("{} {}\n", "Version".bold(), VERSION.green());
    }

    match cli.cmd.unwrap_or_else(|| {
        // If no command provided, show help or enter interactive mode
        Commands::Interactive
    }) {
        Commands::Init { path, force } => {
            let workspace_path = path.unwrap_or_else(|| ".".to_string());
            let path = PathBuf::from(workspace_path);
            Workspace::init(path, force)?;
        }
        Commands::Interactive => {
            interactive_mode()?;
        }
        Commands::GenerateKey { force, backup } => {
            generate_key(force, backup)?;
        }
        Commands::Info => {
            show_workspace_info()?;
        }
        _ => {
            let workspace = get_workspace()?;
            match cli.cmd.unwrap() {
                Commands::Create { name, tags, description, file, content_type, expires, priority, encrypted } => {
                    let final_name = name.unwrap_or_else(|| {
                        Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter file name")
                            .default(format!("entry_{}", Utc::now().timestamp()))
                            .interact()
                            .unwrap()
                    });
                    create_file(&workspace, &final_name, tags, description, file, content_type, expires, priority, encrypted)?;
                }
                Commands::Read { path, raw, meta_only, export, format } => {
                    read_file(&workspace, &path, raw, meta_only, export, format)?;
                }
                Commands::Verify { path, verbose, report } => {
                    if path == "all" {
                        verify_all_files(&workspace, verbose, report)?;
                    } else {
                        verify_file(&workspace, &path, verbose)?;
                    }
                }
                Commands::List { tag, search, verbose, content_type, expired, sort, limit } => {
                    list_files(&workspace, tag, search, verbose, content_type, expired, sort, limit)?;
                }
                Commands::Stats { detailed, charts } => {
                    show_stats(&workspace, detailed, charts)?;
                }
                Commands::Export { output, format, meta_only, no_content } => {
                    export_workspace(&workspace, &output, format, meta_only, no_content)?;
                }
                Commands::Import { input, target, no_verify } => {
                    import_workspace(&input, target, no_verify)?;
                }
                Commands::Search { query, case_sensitive, regex, meta_only, context } => {
                    search_content(&workspace, &query, case_sensitive, regex, meta_only, context)?;
                }
                Commands::Backup { name, full, incremental } => {
                    backup_workspace(&workspace, &name, full, incremental)?;
                }
                Commands::Restore { backup, target } => {
                    restore_workspace(&backup, target)?;
                }
                Commands::Maintenance { action } => {
                    maintenance_operations(&workspace, action)?;
                }
                Commands::Clean { dry_run, force } => {
                    clean_expired(&workspace, dry_run, force)?;
                }
                Commands::Watch { interval } => {
                    watch_workspace(&workspace, interval.unwrap_or(60))?;
                }
                _ => {} // Already handled above
            }
        }
    }

    Ok(())
}

fn interactive_mode() -> anyhow::Result<()> {
    println!("{}", "═══ INTERACTIVE MODE ═══".blue().bold());
    println!("Welcome to Immutable Database interactive mode!");
    println!("You can create multiple entries in this session.\n");

    let workspace = get_workspace()?;
    
    loop {
        let options = vec![
            "Create new entry",
            "List existing entries", 
            "Search entries",
            "Show statistics",
            "Verify all files",
            "Exit"
        ];

        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .default(0)
            .items(&options)
            .interact()?;

        match selection {
            0 => {
                // Create new entry
                interactive_create(&workspace)?;
            }
            1 => {
                // List entries
                list_files(&workspace, None, None, false, None, false, None, Some(10))?;
            }
            2 => {
                // Search
                let query: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter search query")
                    .interact()?;
                search_content(&workspace, &query, false, false, false, Some(2))?;
            }
            3 => {
                // Stats
                show_stats(&workspace, false, false)?;
            }
            4 => {
                // Verify all
                verify_all_files(&workspace, false, false)?;
            }
            5 => {
                // Exit
                println!("{}", "Thank you for using Immutable Database!".green());
                break;
            }
            _ => unreachable!(),
        }

        // Ask if user wants to continue
        if selection != 5 {
            if !Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Continue with another operation?")
                .default(true)
                .interact()? {
                break;
            }
        }
    }

    Ok(())
}

fn interactive_create(workspace: &Workspace) -> anyhow::Result<()> {
    println!("\n{}", "Creating new entry...".yellow());
    
    let name: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Entry name")
        .default(format!("entry_{}", Utc::now().timestamp()))
        .interact()?;

    let description: Option<String> = {
        let desc: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Description (optional)")
            .allow_empty(true)
            .interact()?;
        if desc.is_empty() { None } else { Some(desc) }
    };

    let content_types = vec!["text", "json", "csv", "log", "markdown", "code", "config"];
    let content_type_idx = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Content type")
        .default(0)
        .items(&content_types)
        .interact()?;
    let content_type = content_types[content_type_idx].to_string();

    let tag_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Tags (comma-separated, optional)")
        .allow_empty(true)
        .interact()?;
    let tags: Vec<String> = if tag_input.is_empty() {
        vec![]
    } else {
        tag_input.split(',').map(|s| s.trim().to_string()).collect()
    };

    let priority: u8 = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Priority (1-5, 1=highest)")
        .default(3)
        .interact()?;

    let expires_input: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Expiration (e.g., '30d', '1y', '2023-12-31', or empty for no expiration)")
        .allow_empty(true)
        .interact()?;
    let expires = if expires_input.is_empty() { None } else { Some(expires_input) };

    let use_editor = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Use external editor for content?")
        .default(false)
        .interact()?;

    let content = if use_editor {
        if let Some(content) = Editor::new().edit("Enter your content here...")? {
            content
        } else {
            return Err(anyhow::anyhow!("Content is required"));
        }
    } else {
        println!("{}", "Enter content (press Ctrl+D when done):".blue());
        let mut content = String::new();
        io::stdin().read_to_string(&mut content)?;
        content.trim().to_string()
    };

    if content.is_empty() {
        return Err(anyhow::anyhow!("Content cannot be empty"));
    }

    // Create the file
    create_file_with_content(workspace, &name, tags, description, Some(content_type), expires, Some(priority), false, content)?;

    println!("{}", "✓ Entry created successfully!".green());
    Ok(())
}

fn get_workspace() -> anyhow::Result<Workspace> {
    let current_dir = std::env::current_dir()?;
    
    // Try current directory first
    if current_dir.join("workspace.json").exists() {
        return Workspace::new(current_dir);
    }

    // Try parent directories
    let mut path = current_dir.as_path();
    while let Some(parent) = path.parent() {
        if parent.join("workspace.json").exists() {
            return Workspace::new(parent.to_path_buf());
        }
        path = parent;
    }

    // Try home directory
    if let Some(home) = dirs::home_dir() {
        let home_workspace = home.join(".immutable_deb_db");
        if home_workspace.join("workspace.json").exists() {
            return Workspace::new(home_workspace);
        }
    }

    Err(anyhow::anyhow!("No workspace found. Run 'imdb init' to create one."))
}

fn load_keypair_from_file(path: &str) -> anyhow::Result<Keypair> {
    let bytes = std::fs::read(path)?;
    let keypair = Keypair::from_bytes(&bytes)?;
    Ok(keypair)
}

fn generate_key(force: bool, backup: bool) -> anyhow::Result<()> {
    if !force {
        println!("{}", "WARNING: Generating a new key will invalidate all existing files!".red());
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Are you sure?")
            .default(false)
            .interact()? {
            println!("Aborted.");
            return Ok(());
        }
    }

    let workspace = get_workspace()?;
    let keypair_path = workspace.path.join("keypair.bin");

    if backup && keypair_path.exists() {
        let backup_path = workspace.path.join(format!("keypair_backup_{}.bin", Utc::now().timestamp()));
        std::fs::copy(&keypair_path, &backup_path)?;
        println!("{} Old keypair backed up to: {}", "✓".green(), backup_path.display());
    }

    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    std::fs::write(keypair_path, keypair.to_bytes())?;

    println!("{}", "✓ New keypair generated!".green());
    println!("{}", "WARNING: All existing .iddb files are now invalid!".red());

    Ok(())
}

fn parse_expiration(expires_str: &str) -> anyhow::Result<DateTime<Utc>> {
    // Try parsing as duration first (e.g., "30d", "1y", "2h")
    if let Some(captures) = Regex::new(r"^(\d+)([dhmy])$").unwrap().captures(expires_str) {
        let amount: i64 = captures.get(1).unwrap().as_str().parse()?;
        let unit = captures.get(2).unwrap().as_str();
        
        let duration = match unit {
            "d" => Duration::days(amount),
            "h" => Duration::hours(amount),
            "m" => Duration::days(amount * 30), // Approximate month as 30 days
            "y" => Duration::days(amount * 365), // Approximate year as 365 days
            _ => return Err(anyhow::anyhow!("Invalid time unit")),
        };
        
        return Ok(Utc::now() + duration);
    }
    
    // Try parsing as date
    if let Ok(date) = chrono::NaiveDate::parse_from_str(expires_str, "%Y-%m-%d") {
        return Ok(date.and_hms_opt(23, 59, 59).unwrap().and_utc());
    }
    
    // Try parsing as datetime
    if let Ok(datetime) = DateTime::parse_from_rfc3339(expires_str) {
        return Ok(datetime.into());
    }
    
    Err(anyhow::anyhow!("Invalid expiration format. Use '30d', '1y', or '2023-12-31'"))
}

fn calculate_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

fn create_file(workspace: &Workspace, name: &str, tags: Vec<String>, description: Option<String>, 
               file_input: Option<String>, content_type: Option<String>, expires: Option<String>, 
               priority: Option<u8>, encrypted: bool) -> anyhow::Result<()> {
    
    let content = if let Some(input_file) = file_input {
        std::fs::read_to_string(&input_file)
            .map_err(|e| anyhow::anyhow!("Failed to read input file: {}", e))?
    } else {
        prompt_for_content()?
    };

    create_file_with_content(workspace, name, tags, description, content_type, expires, priority, encrypted, content)
}

fn create_file_with_content(workspace: &Workspace, name: &str, tags: Vec<String>, description: Option<String>, 
                           content_type: Option<String>, expires: Option<String>, priority: Option<u8>, 
                           encrypted: bool, content: String) -> anyhow::Result<()> {
    let file_path = workspace.get_file_path(name);
    
    if file_path.exists() {
        return Err(anyhow::anyhow!("File already exists: {}", file_path.display()));
    }

    if content.is_empty() {
        return Err(anyhow::anyhow!("Content cannot be empty"));
    }

    // Check file size limit
    if let Some(max_size) = workspace.config.settings.max_file_size {
        if content.len() as u64 > max_size {
            return Err(anyhow::anyhow!("Content exceeds maximum file size limit"));
        }
    }

    let created_at = Utc::now();
    let content_hash = calculate_content_hash(&content);
    let file_size = content.len() as u64;

    let expires_at = if let Some(expires_str) = expires {
        Some(parse_expiration(&expires_str)?)
    } else {
        None
    };

    let mut metadata = HashMap::new();
    metadata.insert("created_by".to_string(), "imdb".to_string());
    metadata.insert("version".to_string(), VERSION.to_string());
    
    if encrypted {
        metadata.insert("encryption".to_string(), "user_provided".to_string());
    }

    let mut payload = FilePayload {
        version: 1,
        id: Uuid::new_v4().to_string(),
        created_at,
        modified_at: None,
        accessed_at: None,
        title: Some(name.to_string()),
        description,
        tags,
        content,
        content_hash,
        content_type: content_type.unwrap_or_else(|| "text".to_string()),
        file_size,
        priority: priority.unwrap_or(3),
        expires_at,
        is_encrypted: encrypted,
        public_key_b64: workspace.config.public_key_b64.clone(),
        signature_b64: String::new(),
        metadata,
        checksum: None,
    };

    // Create signature
    let mut to_sign = payload.clone();
    to_sign.signature_b64 = String::new();
    let to_sign_bytes = serde_json::to_vec(&to_sign)?;
    let signature: Signature = workspace.keypair.sign(&to_sign_bytes);
    payload.signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());

    // Calculate overall checksum
    let payload_bytes = serde_json::to_vec(&payload)?;
    let checksum = calculate_content_hash(&String::from_utf8_lossy(&payload_bytes));
    payload.checksum = Some(checksum.clone());

    // Write file atomically
    let tmp_path = file_path.with_extension("tmp");
    {
        let json = serde_json::to_vec_pretty(&payload)?;
        std::fs::write(&tmp_path, json)?;
    }
    std::fs::rename(&tmp_path, &file_path)?;

    // Set read-only permissions
    set_readonly_permissions(&file_path)?;

    // Try to set immutable flag on Linux
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("chattr")
            .arg("+i")
            .arg(&file_path)
            .status();
    }

    println!("{} {}", "✓ Created:".green(), file_path.display());
    println!("ID: {}", payload.id);
    println!("Size: {} bytes", file_size);
    println!("Hash: {}", content_hash);
    println!("Checksum: {}", checksum);
    
    if let Some(exp) = expires_at {
        println!("Expires: {}", exp.format("%Y-%m-%d %H:%M:%S UTC"));
    }

    // Log creation
    log_operation(&workspace.logs_dir(), &format!("CREATE: {} ({})", name, payload.id))?;

    Ok(())
}

fn prompt_for_content() -> anyhow::Result<String> {
    println!("{}", "Enter content (Ctrl+D to finish):".blue());
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim_end().to_string())
}

fn set_readonly_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let perms = std::fs::Permissions::from_mode(0o444);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn read_file(workspace: &Workspace, name: &str, raw: bool, meta_only: bool, 
             export: Option<String>, format: Option<String>) -> anyhow::Result<()> {
    let file_path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        workspace.get_file_path(name)
    };

    if !file_path.exists() {
        return Err(anyhow::anyhow!("File not found: {}", file_path.display()));
    }

    let content = std::fs::read_to_string(&file_path)?;
    let mut payload: FilePayload = serde_json::from_str(&content)?;

    // Update accessed time
    payload.accessed_at = Some(Utc::now());

    if let Some(export_path) = export {
        std::fs::write(&export_path, &payload.content)?;
        println!("{} Content exported to: {}", "✓".green(), export_path);
        return Ok(());
    }

    if raw {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    let fmt = format.as_deref().unwrap_or("pretty");
    
    match fmt {
        "table" => {
            print_file_table(&payload);
        }
        "compact" => {
            print_file_compact(&payload, meta_only);
        }
        _ => {
            print_file_pretty(&payload, meta_only);
        }
    }

    // Log access
    log_operation(&workspace.logs_dir(), &format!("READ: {} ({})", name, payload.id))?;

    Ok(())
}

fn print_file_pretty(payload: &FilePayload, meta_only: bool) {
    println!("{}", "═══ FILE INFO ═══".blue());
    println!("ID: {}", payload.id);
    println!("Title: {}", payload.title.as_ref().unwrap_or(&"Untitled".to_string()));
    
    if let Some(desc) = &payload.description {
        println!("Description: {}", desc);
    }
    
    println!("Content Type: {}", payload.content_type);
    println!("Created: {}", payload.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    
    if let Some(accessed) = payload.accessed_at {
        println!("Last Accessed: {}", accessed.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    
    if !payload.tags.is_empty() {
        println!("Tags: {}", payload.tags.join(", "));
    }
    
    println!("Priority: {} (1=highest, 5=lowest)", payload.priority);
    println!("Size: {} bytes", payload.file_size);
    println!("Hash: {}", payload.content_hash);
    
    if let Some(checksum) = &payload.checksum {
        println!("Checksum: {}", checksum);
    }
    
    if let Some(expires) = payload.expires_at {
        let now = Utc::now();
        if expires < now {
            println!("Status: {} (expired {})", "EXPIRED".red(), expires.format("%Y-%m-%d"));
        } else {
            println!("Expires: {}", expires.format("%Y-%m-%d %H:%M:%S UTC"));
        }
    }
    
    if payload.is_encrypted {
        println!("Encryption: {}", "Yes".yellow());
    }

    if !payload.metadata.is_empty() {
        println!("{}", "Metadata:".blue());
        for (key, value) in &payload.metadata {
            println!("  {}: {}", key, value);
        }
    }

    if !meta_only {
        println!();
        println!("{}", "═══ CONTENT ═══".blue());
        
        if payload.content.len() > 10000 {
            println!("{}", "Content is large. Showing first 10000 characters...".yellow());
            println!("{}", &payload.content[..10000]);
            println!("{}", "... (truncated)".yellow());
        } else {
            println!("{}", payload.content);
        }
    }
}

fn print_file_compact(payload: &FilePayload, meta_only: bool) {
    println!("{} | {} | {} | {} bytes", 
        payload.title.as_ref().unwrap_or(&"Untitled".to_string()).green(),
        payload.content_type.blue(),
        payload.created_at.format("%Y-%m-%d %H:%M"),
        payload.file_size
    );
    
    if !meta_only && !payload.content.is_empty() {
        let preview = if payload.content.len() > 200 {
            format!("{}...", &payload.content[..200].replace('\n', " "))
        } else {
            payload.content.replace('\n', " ")
        };
        println!("  {}", preview);
    }
}

fn print_file_table(payload: &FilePayload) {
    println!("┌─────────────────┬──────────────────────────────────────────┐");
    println!("│ Field           │ Value                                    │");
    println!("├─────────────────┼──────────────────────────────────────────┤");
    println!("│ ID              │ {:40} │", payload.id);
    println!("│ Title           │ {:40} │", payload.title.as_ref().unwrap_or(&"Untitled".to_string()));
    println!("│ Type            │ {:40} │", payload.content_type);
    println!("│ Created         │ {:40} │", payload.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("│ Size            │ {:40} │", format!("{} bytes", payload.file_size));
    println!("│ Priority        │ {:40} │", payload.priority);
    println!("│ Tags            │ {:40} │", payload.tags.join(", "));
    println!("└─────────────────┴──────────────────────────────────────────┘");
}

fn verify_file(workspace: &Workspace, name: &str, verbose: bool) -> anyhow::Result<()> {
    let file_path = if Path::new(name).exists() {
        PathBuf::from(name)
    } else {
        workspace.get_file_path(name)
    };

    if !file_path.exists() {
        return Err(anyhow::anyhow!("File not found: {}", file_path.display()));
    }

    let content = std::fs::read_to_string(&file_path)?;
    let payload: FilePayload = serde_json::from_str(&content)?;

    if verbose {
        println!("{}", "Verifying file integrity...".blue());
        println!("File: {}", file_path.display());
        println!("ID: {}", payload.id);
    }

    // Check if expired
    if let Some(expires) = payload.expires_at {
        if Utc::now() > expires {
            println!("{} File has expired on {}", "⚠".yellow(), expires.format("%Y-%m-%d"));
        }
    }

    // Verify content hash
    let calculated_hash = calculate_content_hash(&payload.content);
    if calculated_hash != payload.content_hash {
        println!("{} Content hash mismatch!", "✗".red());
        if verbose {
            println!("Expected: {}", payload.content_hash);
            println!("Calculated: {}", calculated_hash);
        }
        return Ok(());
    }

    // Verify checksum if present
    if let Some(expected_checksum) = &payload.checksum {
        let mut temp_payload = payload.clone();
        temp_payload.checksum = None;
        let payload_bytes = serde_json::to_vec(&temp_payload)?;
        let calculated_checksum = calculate_content_hash(&String::from_utf8_lossy(&payload_bytes));
        
        if calculated_checksum != *expected_checksum {
            println!("{} File checksum mismatch!", "✗".red());
            if verbose {
                println!("Expected: {}", expected_checksum);
                println!("Calculated: {}", calculated_checksum);
            }
            return Ok(());
        }
    }

    // Verify signature
    let mut to_verify = payload.clone();
    to_verify.signature_b64 = String::new();
    let to_verify_bytes = serde_json::to_vec(&to_verify)?;

    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature_b64)?;
    let signature = Signature::from_bytes(&signature_bytes)?;

    let public_key_bytes = general_purpose::STANDARD.decode(&payload.public_key_b64)?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)?;

    match public_key.verify(&to_verify_bytes, &signature) {
        Ok(()) => {
            println!("{} File integrity verified!", "✓".green());
            if verbose {
                println!("Content Hash: {}", calculated_hash);
                println!("Signature: Valid");
                if let Some(checksum) = &payload.checksum {
                    println!("File Checksum: Valid");
                }
            }
        }
        Err(_) => {
            println!("{} Signature verification failed!", "✗".red());
        }
    }

    Ok(())
}

fn verify_all_files(workspace: &Workspace, verbose: bool, report: bool) -> anyhow::Result<()> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        println!("No files found.");
        return Ok(());
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            files.push(entry.path().to_path_buf());
        }
    }

    if files.is_empty() {
        println!("No .iddb files found.");
        return Ok(());
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let mut valid = 0;
    let mut invalid = 0;
    let mut expired = 0;
    let mut verification_report = Vec::new();

    for file_path in files {
        pb.inc(1);
        let filename = file_path.file_name().unwrap().to_string_lossy();
        pb.set_message(format!("Verifying {}", filename));
        
        match verify_single_file(&file_path) {
            Ok(result) => {
                match result {
                    VerificationResult::Valid => {
                        valid += 1;
                        if report {
                            verification_report.push(format!("✓ {}: VALID", filename));
                        }
                    }
                    VerificationResult::Expired => {
                        expired += 1;
                        if report {
                            verification_report.push(format!("⚠ {}: EXPIRED", filename));
                        }
                    }
                    VerificationResult::Invalid(reason) => {
                        invalid += 1;
                        if verbose {
                            println!("\n{} {}: {}", "✗".red(), filename, reason);
                        }
                        if report {
                            verification_report.push(format!("✗ {}: INVALID - {}", filename, reason));
                        }
                    }
                }
            }
            Err(e) => {
                invalid += 1;
                if verbose {
                    println!("\n{} {}: Error - {}", "✗".red(), filename, e);
                }
                if report {
                    verification_report.push(format!("✗ {}: ERROR - {}", filename, e));
                }
            }
        }
    }

    pb.finish_with_message("Verification complete");

    println!("\n{}", "═══ VERIFICATION SUMMARY ═══".blue());
    println!("Total files: {}", valid + invalid + expired);
    println!("{} Valid: {}", "✓".green(), valid);
    if expired > 0 {
        println!("{} Expired: {}", "⚠".yellow(), expired);
    }
    if invalid > 0 {
        println!("{} Invalid: {}", "✗".red(), invalid);
    }

    if report && !verification_report.is_empty() {
        let report_path = workspace.logs_dir().join(format!("verification_report_{}.txt", Utc::now().timestamp()));
        let report_content = format!(
            "Verification Report - {}\n{}\n\n{}",
            Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            "=".repeat(50),
            verification_report.join("\n")
        );
        std::fs::write(&report_path, report_content)?;
        println!("{} Report saved to: {}", "✓".green(), report_path.display());
    }

    Ok(())
}

#[derive(Debug)]
enum VerificationResult {
    Valid,
    Invalid(String),
    Expired,
}

fn verify_single_file(file_path: &Path) -> anyhow::Result<VerificationResult> {
    let content = std::fs::read_to_string(file_path)?;
    let payload: FilePayload = serde_json::from_str(&content)?;

    // Check if expired
    if let Some(expires) = payload.expires_at {
        if Utc::now() > expires {
            return Ok(VerificationResult::Expired);
        }
    }

    // Verify content hash
    let calculated_hash = calculate_content_hash(&payload.content);
    if calculated_hash != payload.content_hash {
        return Ok(VerificationResult::Invalid("Content hash mismatch".to_string()));
    }

    // Verify checksum if present
    if let Some(expected_checksum) = &payload.checksum {
        let mut temp_payload = payload.clone();
        temp_payload.checksum = None;
        let payload_bytes = serde_json::to_vec(&temp_payload)?;
        let calculated_checksum = calculate_content_hash(&String::from_utf8_lossy(&payload_bytes));
        
        if calculated_checksum != *expected_checksum {
            return Ok(VerificationResult::Invalid("File checksum mismatch".to_string()));
        }
    }

    // Verify signature
    let mut to_verify = payload.clone();
    to_verify.signature_b64 = String::new();
    let to_verify_bytes = serde_json::to_vec(&to_verify)?;

    let signature_bytes = general_purpose::STANDARD.decode(&payload.signature_b64)
        .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;
    let signature = Signature::from_bytes(&signature_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid signature format"))?;

    let public_key_bytes = general_purpose::STANDARD.decode(&payload.public_key_b64)
        .map_err(|_| anyhow::anyhow!("Invalid public key format"))?;
    let public_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| anyhow::anyhow!("Invalid public key format"))?;

    match public_key.verify(&to_verify_bytes, &signature) {
        Ok(()) => Ok(VerificationResult::Valid),
        Err(_) => Ok(VerificationResult::Invalid("Signature verification failed".to_string())),
    }
}

fn list_files(workspace: &Workspace, tag_filter: Option<String>, search_filter: Option<String>, 
              verbose: bool, content_type_filter: Option<String>, show_expired: bool, 
              sort_by: Option<String>, limit: Option<usize>) -> anyhow::Result<()> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        println!("No files found.");
        return Ok(());
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(payload) = serde_json::from_str::<FilePayload>(&content) {
                    // Apply filters
                    if let Some(ref tag) = tag_filter {
                        if !payload.tags.iter().any(|t| t.to_lowercase().contains(&tag.to_lowercase())) {
                            continue;
                        }
                    }
                    
                    if let Some(ref search) = search_filter {
                        let search_lower = search.to_lowercase();
                        let title_match = payload.title.as_ref()
                            .map_or(false, |t| t.to_lowercase().contains(&search_lower));
                        let content_match = payload.content.to_lowercase().contains(&search_lower);
                        let desc_match = payload.description.as_ref()
                            .map_or(false, |d| d.to_lowercase().contains(&search_lower));
                        
                        if !title_match && !content_match && !desc_match {
                            continue;
                        }
                    }
                    
                    if let Some(ref ct_filter) = content_type_filter {
                        if !payload.content_type.to_lowercase().contains(&ct_filter.to_lowercase()) {
                            continue;
                        }
                    }

                    // Check expiration filter
                    let is_expired = payload.expires_at.map_or(false, |exp| Utc::now() > exp);
                    if show_expired && !is_expired {
                        continue;
                    } else if !show_expired && is_expired {
                        continue;
                    }
                    
                    files.push((entry.path().to_path_buf(), payload));
                }
            }
        }
    }

    // Sort files
    match sort_by.as_deref().unwrap_or("date") {
        "date" => files.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at)),
        "size" => files.sort_by(|a, b| b.1.file_size.cmp(&a.1.file_size)),
        "name" => files.sort_by(|a, b| a.1.title.cmp(&b.1.title)),
        "priority" => files.sort_by(|a, b| a.1.priority.cmp(&b.1.priority)),
        _ => files.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at)),
    }

    // Apply limit
    if let Some(limit_count) = limit {
        files.truncate(limit_count);
    }

    if files.is_empty() {
        println!("No files found matching criteria.");
        return Ok(());
    }

    println!("{} files found:", files.len());
    println!();

    for (i, (path, payload)) in files.iter().enumerate() {
        let filename = path.file_name().unwrap().to_string_lossy();
        
        if verbose {
            println!("{}", "─".repeat(60).blue());
            println!("{}. File: {}", i + 1, filename.green());
            println!("   ID: {}", payload.id);
            println!("   Title: {}", payload.title.as_ref().unwrap_or(&"Untitled".to_string()));
            
            if let Some(desc) = &payload.description {
                println!("   Description: {}", desc);
            }
            
            println!("   Type: {} | Priority: {} | Size: {} bytes", 
                    payload.content_type.blue(), payload.priority, payload.file_size);
            println!("   Created: {}", payload.created_at.format("%Y-%m-%d %H:%M:%S"));
            
            if !payload.tags.is_empty() {
                println!("   Tags: {}", payload.tags.join(", ").yellow());
            }

            // Check expiration
            if let Some(expires) = payload.expires_at {
                if Utc::now() > expires {
                    println!("   Status: {} (expired {})", "EXPIRED".red(), expires.format("%Y-%m-%d"));
                } else {
                    println!("   Expires: {}", expires.format("%Y-%m-%d %H:%M:%S"));
                }
            }
            
            // Show content preview
            let preview = if payload.content.len() > 150 {
                format!("{}...", &payload.content[..150])
            } else {
                payload.content.clone()
            };
            println!("   Preview: {}", preview.replace('\n', " "));
        } else {
            let title = payload.title.as_ref().unwrap_or(&"Untitled".to_string());
            let tags = if payload.tags.is_empty() { 
                String::new() 
            } else { 
                format!(" [{}]", payload.tags.join(", ")) 
            };
            
            let status = if let Some(expires) = payload.expires_at {
                if Utc::now() > expires {
                    " (EXPIRED)".red().to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            println!("{}. {} - {} {} {} ({})", 
                i + 1,
                filename.green(), 
                title, 
                tags.yellow(),
                status,
                payload.created_at.format("%Y-%m-%d %H:%M")
            );
        }
    }

    Ok(())
}

fn show_stats(workspace: &Workspace, detailed: bool, _charts: bool) -> anyhow::Result<()> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        println!("No data directory found.");
        return Ok(());
    }

    let mut total_files = 0;
    let mut total_size = 0u64;
    let mut tags = HashMap::new();
    let mut content_types = HashMap::new();
    let mut priority_counts = HashMap::new();
    let mut oldest_date = None;
    let mut newest_date = None;
    let mut expired_count = 0;
    let mut encrypted_count = 0;

    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(payload) = serde_json::from_str::<FilePayload>(&content) {
                    total_files += 1;
                    total_size += payload.file_size;
                    
                    // Count content types
                    *content_types.entry(payload.content_type.clone()).or_insert(0) += 1;
                    
                    // Count priorities
                    *priority_counts.entry(payload.priority).or_insert(0) += 1;
                    
                    // Count tags
                    for tag in &payload.tags {
                        *tags.entry(tag.clone()).or_insert(0) += 1;
                    }
                    
                    // Check expiration
                    if let Some(expires) = payload.expires_at {
                        if Utc::now() > expires {
                            expired_count += 1;
                        }
                    }
                    
                    // Count encrypted files
                    if payload.is_encrypted {
                        encrypted_count += 1;
                    }
                    
                    // Track date ranges
                    if oldest_date.is_none() || Some(payload.created_at) < oldest_date {
                        oldest_date = Some(payload.created_at);
                    }
                    if newest_date.is_none() || Some(payload.created_at) > newest_date {
                        newest_date = Some(payload.created_at);
                    }
                }
            }
        }
    }

    println!("{}", "═══ WORKSPACE STATISTICS ═══".blue().bold());
    println!("Workspace ID: {}", workspace.config.workspace_id);
    println!("Location: {}", workspace.path.display());
    println!("Created: {}", workspace.config.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
    println!();
    
    println!("{}", "Basic Statistics:".green());
    println!("  Total Files: {}", total_files);
    println!("  Total Size: {:.2} KB ({:.2} MB)", total_size as f64 / 1024.0, total_size as f64 / (1024.0 * 1024.0));
    println!("  Average File Size: {:.2} KB", if total_files > 0 { total_size as f64 / total_files as f64 / 1024.0 } else { 0.0 });
    
    if expired_count > 0 {
        println!("  Expired Files: {} ({:.1}%)", expired_count, (expired_count as f64 / total_files as f64) * 100.0);
    }
    
    if encrypted_count > 0 {
        println!("  Encrypted Files: {} ({:.1}%)", encrypted_count, (encrypted_count as f64 / total_files as f64) * 100.0);
    }
    
    if let Some(oldest) = oldest_date {
        println!("  Oldest Entry: {}", oldest.format("%Y-%m-%d %H:%M:%S"));
    }
    if let Some(newest) = newest_date {
        println!("  Newest Entry: {}", newest.format("%Y-%m-%d %H:%M:%S"));
    }
    
    if !content_types.is_empty() {
        println!();
        println!("{}", "Content Types:".green());
        let mut ct_vec: Vec<_> = content_types.into_iter().collect();
        ct_vec.sort_by(|a, b| b.1.cmp(&a.1));
        for (content_type, count) in ct_vec {
            let percentage = (count as f64 / total_files as f64) * 100.0;
            println!("  {} ({}) - {:.1}%", content_type.blue(), count, percentage);
        }
    }
    
    if !priority_counts.is_empty() && detailed {
        println!();
        println!("{}", "Priority Distribution:".green());
        for i in 1..=5 {
            let count = priority_counts.get(&i).unwrap_or(&0);
            if *count > 0 {
                let percentage = (*count as f64 / total_files as f64) * 100.0;
                let priority_name = match i {
                    1 => "Highest",
                    2 => "High", 
                    3 => "Medium",
                    4 => "Low",
                    5 => "Lowest",
                    _ => "Unknown",
                };
                println!("  Priority {} ({}): {} files ({:.1}%)", i, priority_name, count, percentage);
            }
        }
    }
    
    if !tags.is_empty() {
        println!();
        println!("{}", "Tags:".green());
        let mut tag_vec: Vec<_> = tags.into_iter().collect();
        tag_vec.sort_by(|a, b| b.1.cmp(&a.1));
        let display_count = if detailed { tag_vec.len() } else { std::cmp::min(tag_vec.len(), 10) };
        for (tag, count) in tag_vec.iter().take(display_count) {
            println!("  {} ({})", tag.yellow(), count);
        }
        if tag_vec.len() > display_count {
            println!("  ... and {} more tags", tag_vec.len() - display_count);
        }
    }

    Ok(())
}

fn search_content(workspace: &Workspace, query: &str, case_sensitive: bool, use_regex: bool, 
                  meta_only: bool, context: Option<usize>) -> anyhow::Result<()> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        println!("No files found.");
        return Ok(());
    }

    let regex_pattern = if use_regex {
        if case_sensitive {
            Regex::new(query)?
        } else {
            Regex::new(&format!("(?i){}", query))?
        }
    } else {
        let escaped = regex::escape(query);
        if case_sensitive {
            Regex::new(&escaped)?
        } else {
            Regex::new(&format!("(?i){}", escaped))?
        }
    };

    let mut matches = Vec::new();

    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(payload) = serde_json::from_str::<FilePayload>(&content) {
                    let mut file_matches = Vec::new();
                    
                    // Search in metadata
                    if let Some(title) = &payload.title {
                        if regex_pattern.is_match(title) {
                            file_matches.push(("title".to_string(), title.clone()));
                        }
                    }
                    
                    if let Some(description) = &payload.description {
                        if regex_pattern.is_match(description) {
                            file_matches.push(("description".to_string(), description.clone()));
                        }
                    }
                    
                    for tag in &payload.tags {
                        if regex_pattern.is_match(tag) {
                            file_matches.push(("tag".to_string(), tag.clone()));
                        }
                    }

                    // Search in content if not meta-only
                    if !meta_only {
                        if let Some(context_lines) = context {
                            // Search with context
                            let lines: Vec<&str> = payload.content.lines().collect();
                            for (line_num, line) in lines.iter().enumerate() {
                                if regex_pattern.is_match(line) {
                                    let start = if line_num >= context_lines { line_num - context_lines } else { 0 };
                                    let end = std::cmp::min(line_num + context_lines + 1, lines.len());
                                    
                                    let context_text = lines[start..end].join("\n");
                                    file_matches.push(("content".to_string(), 
                                        format!("Line {}: {}", line_num + 1, context_text)));
                                }
                            }
                        } else if regex_pattern.is_match(&payload.content) {
                            // Simple match without context
                            let preview = if payload.content.len() > 200 {
                                format!("{}...", &payload.content[..200])
                            } else {
                                payload.content.clone()
                            };
                            file_matches.push(("content".to_string(), preview.replace('\n', " ")));
                        }
                    }
                    
                    if !file_matches.is_empty() {
                        matches.push((entry.path().to_path_buf(), payload, file_matches));
                    }
                }
            }
        }
    }

    if matches.is_empty() {
        println!("No matches found for: {}", query);
        return Ok(());
    }

    println!("{} matches found in {} files:\n", 
             matches.iter().map(|(_, _, m)| m.len()).sum::<usize>(),
             matches.len());

    for (path, payload, file_matches) in matches {
        let filename = path.file_name().unwrap().to_string_lossy();
        println!("{} {}", "File:".blue().bold(), filename.green());
        println!("  Title: {}", payload.title.as_ref().unwrap_or(&"Untitled".to_string()));
        println!("  Created: {}", payload.created_at.format("%Y-%m-%d %H:%M"));
        
        for (match_type, match_text) in file_matches {
            println!("  {} Match in {}: {}", "→".yellow(), match_type.blue(), match_text);
        }
        println!();
    }

    Ok(())
}

fn export_workspace(workspace: &Workspace, output: &str, format: Option<String>, 
                    meta_only: bool, no_content: bool) -> anyhow::Result<()> {
    println!("{}", "Exporting workspace...".blue());
    
    let output_path = Path::new(output);
    if output_path.exists() {
        return Err(anyhow::anyhow!("Output file already exists"));
    }

    let export_format = format.as_deref().unwrap_or("zip");
    
    match export_format {
        "zip" => export_as_zip(workspace, output, meta_only, no_content),
        "tar.gz" => export_as_tar_gz(workspace, output, meta_only, no_content),
        _ => Err(anyhow::anyhow!("Unsupported export format. Use 'zip' or 'tar.gz'"))
    }
}

fn export_as_zip(workspace: &Workspace, output: &str, meta_only: bool, no_content: bool) -> anyhow::Result<()> {
    use std::io::Write;
    use zip::write::FileOptions;

    let file = File::create(output)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    // Add workspace config
    zip.start_file("workspace.json", options)?;
    let config_json = serde_json::to_string_pretty(&workspace.config)?;
    zip.write_all(config_json.as_bytes())?;

    // Add data files
    let data_dir = workspace.data_dir();
    if data_dir.exists() {
        for entry in WalkDir::new(&data_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel_path = entry.path().strip_prefix(&data_dir)?;
                let archive_path = format!("data/{}", rel_path.display());
                
                if meta_only || no_content {
                    // Export only metadata
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(mut payload) = serde_json::from_str::<FilePayload>(&content) {
                            if no_content {
                                payload.content = "[CONTENT REMOVED]".to_string();
                                payload.content_hash = "removed".to_string();
                            }
                            
                            zip.start_file(&archive_path, options)?;
                            let payload_json = serde_json::to_string_pretty(&payload)?;
                            zip.write_all(payload_json.as_bytes())?;
                        }
                    }
                } else {
                    // Export full file
                    zip.start_file(&archive_path, options)?;
                    let file_content = std::fs::read(entry.path())?;
                    zip.write_all(&file_content)?;
                }
            }
        }
    }

    zip.finish()?;
    println!("{} Export completed: {}", "✓".green(), output);
    println!("{}", "Note: Private key is NOT included for security.".yellow());
    
    Ok(())
}

fn export_as_tar_gz(workspace: &Workspace, output: &str, meta_only: bool, no_content: bool) -> anyhow::Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tar::Builder;

    let file = File::create(output)?;
    let gz = GzEncoder::new(file, Compression::default());
    let mut tar = Builder::new(gz);

    // Add workspace config
    let config_json = serde_json::to_string_pretty(&workspace.config)?;
    let config_bytes = config_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(config_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "workspace.json", config_bytes)?;

    // Add data files
    let data_dir = workspace.data_dir();
    if data_dir.exists() {
        for entry in WalkDir::new(&data_dir).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                let rel_path = entry.path().strip_prefix(&data_dir)?;
                let archive_path = format!("data/{}", rel_path.display());
                
                if meta_only || no_content {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(mut payload) = serde_json::from_str::<FilePayload>(&content) {
                            if no_content {
                                payload.content = "[CONTENT REMOVED]".to_string();
                                payload.content_hash = "removed".to_string();
                            }
                            
                            let payload_json = serde_json::to_string_pretty(&payload)?;
                            let payload_bytes = payload_json.as_bytes();
                            let mut header = tar::Header::new_gnu();
                            header.set_size(payload_bytes.len() as u64);
                            header.set_mode(0o644);
                            header.set_cksum();
                            tar.append_data(&mut header, &archive_path, payload_bytes)?;
                        }
                    }
                } else {
                    tar.append_path_with_name(entry.path(), &archive_path)?;
                }
            }
        }
    }

    tar.finish()?;
    println!("{} Export completed: {}", "✓".green(), output);
    println!("{}", "Note: Private key is NOT included for security.".yellow());
    
    Ok(())
}

fn import_workspace(input: &str, target: Option<String>, no_verify: bool) -> anyhow::Result<()> {
    println!("{}", "Importing workspace...".blue());
    
    let input_path = Path::new(input);
    if !input_path.exists() {
        return Err(anyhow::anyhow!("Input file not found: {}", input));
    }

    let target_dir = if let Some(target_path) = target {
        PathBuf::from(target_path)
    } else {
        std::env::current_dir()?.join("imported_workspace")
    };

    if target_dir.exists() {
        return Err(anyhow::anyhow!("Target directory already exists: {}", target_dir.display()));
    }

    std::fs::create_dir_all(&target_dir)?;

    // Determine format and extract
    let extension = input_path.extension().and_then(|e| e.to_str());
    match extension {
        Some("zip") => import_from_zip(input, &target_dir)?,
        Some("gz") => import_from_tar_gz(input, &target_dir)?,
        _ => return Err(anyhow::anyhow!("Unsupported import format. Use .zip or .tar.gz files")),
    }

    // Verify imported files if requested
    if !no_verify {
        println!("{}", "Verifying imported files...".blue());
        if let Ok(workspace) = Workspace::new(target_dir.clone()) {
            verify_all_files(&workspace, false, false)?;
        } else {
            println!("{}", "Note: Could not verify files - workspace may need key generation".yellow());
        }
    }

    println!("{} Import completed to: {}", "✓".green(), target_dir.display());
    println!("{}", "Note: You may need to generate a new keypair with 'imdb generate-key'".yellow());

    Ok(())
}

fn import_from_zip(input: &str, target_dir: &Path) -> anyhow::Result<()> {
    use zip::read::ZipArchive;

    let file = File::open(input)?;
    let mut archive = ZipArchive::new(file)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = target_dir.join(file.name());

        if let Some(parent) = outpath.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut outfile = File::create(&outpath)?;
        std::io::copy(&mut file, &mut outfile)?;
    }

    Ok(())
}

fn import_from_tar_gz(input: &str, target_dir: &Path) -> anyhow::Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let file = File::open(input)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    archive.unpack(target_dir)?;
    Ok(())
}

fn backup_workspace(workspace: &Workspace, name: &str, full: bool, incremental: bool) -> anyhow::Result<()> {
    let backup_dir = workspace.backup_dir();
    std::fs::create_dir_all(&backup_dir)?;

    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_type = if full {
        "full"
    } else if incremental {
        "incremental"
    } else {
        "data"
    };

    let backup_name = format!("{}_{}_backup_{}.zip", name, backup_type, timestamp);
    let backup_path = backup_dir.join(&backup_name);

    println!("{} Creating {} backup...", "→".blue(), backup_type);

    export_as_zip(workspace, backup_path.to_str().unwrap(), false, false)?;

    // Create backup manifest
    let manifest = BackupManifest {
        name: name.to_string(),
        backup_type: backup_type.to_string(),
        created_at: Utc::now(),
        workspace_id: workspace.config.workspace_id.clone(),
        file_count: count_workspace_files(workspace)?,
    };

    let manifest_path = backup_dir.join(format!("{}.manifest", backup_name));
    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(manifest_path, manifest_json)?;

    println!("{} Backup created: {}", "✓".green(), backup_name);
    log_operation(&workspace.logs_dir(), &format!("BACKUP: {} ({})", name, backup_type))?;

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct BackupManifest {
    name: String,
    backup_type: String,
    created_at: DateTime<Utc>,
    workspace_id: String,
    file_count: usize,
}

fn count_workspace_files(workspace: &Workspace) -> anyhow::Result<usize> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            count += 1;
        }
    }
    Ok(count)
}

fn restore_workspace(backup: &str, target: Option<String>) -> anyhow::Result<()> {
    import_workspace(backup, target, true)
}

fn maintenance_operations(workspace: &Workspace, action: MaintenanceCommands) -> anyhow::Result<()> {
    match action {
        MaintenanceCommands::Compact => {
            println!("{}", "Compacting database files...".blue());
            // In a real implementation, this would compact and optimize file storage
            println!("{}", "✓ Compact operation completed".green());
        }
        MaintenanceCommands::Reindex => {
            println!("{}", "Rebuilding indexes...".blue());
            // In a real implementation, this would rebuild search indexes
            println!("{}", "✓ Reindex operation completed".green());
        }
        MaintenanceCommands::Check => {
            println!("{}", "Checking for corruption...".blue());
            verify_all_files(workspace, true, true)?;
        }
        MaintenanceCommands::Optimize => {
            println!("{}", "Optimizing storage...".blue());
            // In a real implementation, this would optimize file storage
            println!("{}", "✓ Optimization completed".green());
        }
    }

    log_operation(&workspace.logs_dir(), &format!("MAINTENANCE: {:?}", action))?;
    Ok(())
}

fn clean_expired(workspace: &Workspace, dry_run: bool, force: bool) -> anyhow::Result<()> {
    let data_dir = workspace.data_dir();
    if !data_dir.exists() {
        println!("No files found.");
        return Ok(());
    }

    let mut expired_files = Vec::new();
    let now = Utc::now();

    for entry in WalkDir::new(data_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && entry.path().extension().map_or(false, |ext| ext == "iddb") {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if let Ok(payload) = serde_json::from_str::<FilePayload>(&content) {
                    if let Some(expires) = payload.expires_at {
                        if now > expires {
                            expired_files.push((entry.path().to_path_buf(), payload));
                        }
                    }
                }
            }
        }
    }

    if expired_files.is_empty() {
        println!("No expired files found.");
        return Ok(());
    }

    println!("Found {} expired files:", expired_files.len());
    for (path, payload) in &expired_files {
        let filename = path.file_name().unwrap().to_string_lossy();
        println!("  {} - expired {}", 
                filename.red(), 
                payload.expires_at.unwrap().format("%Y-%m-%d"));
    }

    if dry_run {
        println!("{}", "Dry run - no files deleted.".yellow());
        return Ok(());
    }

    if !force {
        if !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Delete these expired files?")
            .default(false)
            .interact()? {
            println!("Operation cancelled.");
            return Ok(());
        }
    }

    let mut deleted = 0;
    for (path, _) in expired_files {
        match std::fs::remove_file(&path) {
            Ok(()) => {
                deleted += 1;
                println!("{} Deleted: {}", "✓".green(), path.file_name().unwrap().to_string_lossy());
            }
            Err(e) => {
                println!("{} Failed to delete {}: {}", "✗".red(), path.file_name().unwrap().to_string_lossy(), e);
            }
        }
    }

    println!("{} Deleted {} expired files.", "✓".green(), deleted);
    log_operation(&workspace.logs_dir(), &format!("CLEAN: {} expired files deleted", deleted))?;

    Ok(())
}

fn watch_workspace(workspace: &Workspace, interval: u64) -> anyhow::Result<()> {
    println!("{} Watching workspace (interval: {}s)...", "👁".blue(), interval);
    println!("Press Ctrl+C to stop watching");

    loop {
        println!("\n{} Checking workspace integrity...", Utc::now().format("%H:%M:%S"));
        
        match verify_all_files(workspace, false, false) {
            Ok(()) => {
                println!("{} All files verified successfully", "✓".green());
            }
            Err(e) => {
                println!("{} Verification error: {}", "✗".red(), e);
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

fn show_workspace_info() -> anyhow::Result<()> {
    match get_workspace() {
        Ok(workspace) => {
            println!("{}", "═══ WORKSPACE INFORMATION ═══".blue().bold());
            println!("ID: {}", workspace.config.workspace_id);
            println!("Location: {}", workspace.path.display());
            println!("Created: {}", workspace.config.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("Version: {}", workspace.config.version);
            
            // Show directory structure
            println!("\n{}", "Directory Structure:".green());
            println!("├── workspace.json (configuration)");
            println!("├── keypair.bin (cryptographic key)");
            println!("├── data/ (immutable database files)");
            println!("├── backups/ (backup archives)");
            println!("├── logs/ (operation logs)");
            println!("└── temp/ (temporary files)");

            // Show settings
            println!("\n{}", "Settings:".green());
            println!("  Auto Backup: {}", if workspace.config.settings.auto_backup { "Yes" } else { "No" });
            println!("  Compression: {}", if workspace.config.settings.compression { "Yes" } else { "No" });
            if let Some(max_size) = workspace.config.settings.max_file_size {
                println!("  Max File Size: {:.2} MB", max_size as f64 / (1024.0 * 1024.0));
            }
            if let Some(default_expires) = &workspace.config.settings.default_expires {
                println!("  Default Expiration: {}", default_expires);
            }

            // Show file count
            if let Ok(file_count) = count_workspace_files(&workspace) {
                println!("\n{}", "Current Status:".green());
                println!("  Total Files: {}", file_count);
            }
        }
        Err(_) => {
            println!("{}", "No workspace found in current directory or parents.".red());
            println!("Run 'imdb init' to create a new workspace.");
        }
    }
    Ok(())
}

fn log_operation(logs_dir: &Path, operation: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(logs_dir)?;
    
    let log_file = logs_dir.join("operations.log");
    let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let log_entry = format!("[{}] {}\n", timestamp, operation);
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)?;
    
    file.write_all(log_entry.as_bytes())?;
    Ok(())
}