#!/bin/bash

# Enhanced Immutable Database Build Script
set -e

echo "🔧 Building Immutable Database Tool (IMDB)..."

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    echo "❌ Cargo/Rust is not installed. Please install Rust first:"
    echo "   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

# Check Rust version
RUST_VERSION=$(rustc --version | cut -d' ' -f2)
REQUIRED_VERSION="1.70.0"
echo "📋 Rust version: $RUST_VERSION"

# Build the project
echo "🏗️  Compiling project..."
cargo build --release

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    
    # Get the binary path
    BINARY_PATH="target/release/immutable_deb_db"
    
    if [ -f "$BINARY_PATH" ]; then
        echo "📦 Binary location: $BINARY_PATH"
        echo "📏 Binary size: $(du -h "$BINARY_PATH" | cut -f1)"
        
        # Ask if user wants to install system-wide
        read -p "🤔 Install system-wide as 'imdb' command? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if command -v sudo &> /dev/null; then
                sudo cp "$BINARY_PATH" /usr/local/bin/imdb
                sudo chmod +x /usr/local/bin/imdb
                echo "✅ Installed to /usr/local/bin/imdb"
                echo "🚀 You can now use 'imdb' command from anywhere!"
            else
                echo "❌ sudo not available. Manual installation required:"
                echo "   cp $BINARY_PATH /usr/local/bin/imdb"
                echo "   chmod +x /usr/local/bin/imdb"
            fi
        else
            echo "💡 To use the tool, run: ./$BINARY_PATH"
            echo "💡 Or add an alias: alias imdb='$(pwd)/$BINARY_PATH'"
        fi
        
        # Show quick start info
        echo ""
        echo "🎯 Quick Start:"
        echo "   1. Initialize workspace: imdb init"
        echo "   2. Interactive mode:    imdb interactive" 
        echo "   3. Create entry:        imdb create test-entry"
        echo "   4. List entries:        imdb list"
        echo "   5. Get help:            imdb --help"
        
    else
        echo "❌ Binary not found at expected location"
        exit 1
    fi
else
    echo "❌ Build failed!"
    exit 1
fi

# Run basic tests if requested
read -p "🧪 Run basic tests? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🧪 Running tests..."
    cargo test
    if [ $? -eq 0 ]; then
        echo "✅ All tests passed!"
    else
        echo "❌ Some tests failed. Check the output above."
    fi
fi

echo ""
echo "🎉 Setup complete!"
echo "📚 Check README.md for detailed usage instructions."