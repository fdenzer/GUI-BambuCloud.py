#!/bin/bash
set -x

# Script to build and run the Rust Egui Bambu Lab Client
# Attempts to install Rust/Cargo and common Egui dependencies on Debian/Ubuntu if not found.

# Exit immediately if a command exits with a non-zero status.
set -e

APP_NAME="egui_frontend"
PROJECT_DIR="egui_frontend"
TARGET_DIR="target"

# Function to install Rust and Cargo
install_rust() {
    echo "Rust/Cargo not found. Attempting to install..."
    if [[ "$(uname)" == "Darwin" ]] && command -v brew &> /dev/null; then # macOS with Homebrew
        echo "Detected macOS with Homebrew. Attempting 'brew install rust'..."
        if brew install rust; then
            echo "Rust/Cargo installed via Homebrew successfully."
            # Homebrew usually handles PATH updates automatically for new shells.
            # For the current shell, if brew's PATH setup hasn't been sourced, cargo might not be found immediately.
            # This is a known caveat with brew installs in scripts sometimes.
            # We'll re-check for cargo, and if not found, advise opening a new terminal.
            if ! command -v cargo &> /dev/null; then
                 echo "Homebrew has installed Rust, but 'cargo' might not be in the current script's PATH yet."
                 echo "Please try opening a new terminal window or sourcing your shell profile, then run this script again."
                 echo "Alternatively, ensure Homebrew's bin directory (e.g., /opt/homebrew/bin or /usr/local/bin) is in your PATH."
                 # We could try to find brew prefix and add to PATH for current script, but it gets complex.
            fi
        else
            echo "'brew install rust' failed. Please try installing manually or check Homebrew."
            exit 1
        fi
    elif [[ "$(uname)" == "Linux" ]] || [[ "$(uname)" =~ "CYGWIN" || "$(uname)" =~ "MINGW" || "$(uname)" =~ "MSYS" ]]; then # Linux or Windows Git Bash/MSYS etc.
        echo "Attempting to install using rustup (official installer)..."
        if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path; then
            source "$HOME/.cargo/env" # Source for current session
            echo "Rust/Cargo installed via rustup successfully."
            echo "You might need to open a new terminal or run 'source \$HOME/.cargo/env' manually in other terminals."
        else
            echo "Rust installation via rustup failed. Please try installing manually from https://www.rust-lang.org/tools/install"
            exit 1
        fi
    else
        echo "Unsupported OS for automatic Rust installation: $(uname)"
        echo "Please install Rust and Cargo manually from https://www.rust-lang.org/tools/install"
        exit 1
    fi
}

# Function to install common Egui dependencies on Debian/Ubuntu
install_egui_deps_debian() {
    echo "Attempting to install Egui dependencies for Debian/Ubuntu..."
    echo "This will require sudo privileges."
    # Common dependencies for egui/winit on Linux with GTK backend
    # libxkbcommon-x11-0 was also needed in our sandbox for keyboard input with Xvfb
    if sudo apt-get update && sudo apt-get install -y libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libgtk-3-dev libdbus-1-dev pkg-config libxkbcommon-x11-0 xvfb; then
        echo "Egui dependencies (including libxkbcommon-x11-0 and xvfb for compatibility) installed successfully."
    else
        echo "Failed to install all Egui dependencies. The application might not build or run correctly."
        echo "Please ensure you have development packages for X11, GTK3, dbus, and libxkbcommon."
    fi
}

# --- Main Script ---

# 1. Check for OS (very basic check for Debian/Ubuntu for dep installation)
OS_RELEASE_FILE="/etc/os-release"
IS_DEBIAN_LIKE=false
if [ -f "$OS_RELEASE_FILE" ]; then
    if grep -qE '^(ID=ubuntu|ID=debian|ID_LIKE=debian)' "$OS_RELEASE_FILE"; then
        IS_DEBIAN_LIKE=true
    fi
fi

# 2. Install Rust/Cargo if not found
if ! command -v cargo &> /dev/null; then
    install_rust
    if ! command -v cargo &> /dev/null; then
        echo "Cargo still not found after installation attempt. Exiting."
        exit 1
    fi
else
    echo "Cargo found. Skipping Rust installation."
fi

# 3. Install Egui system dependencies
if $IS_DEBIAN_LIKE; then
    echo "You appear to be on a Debian-like system."
    # Check for a key dependency like libgtk-3-dev. If missing, offer to install all.
    if ! dpkg -s libgtk-3-dev &> /dev/null || ! dpkg -s libxkbcommon-x11-0 &> /dev/null ; then # Added libxkbcommon check
         read -p "System dependencies for GUI (GTK, X11, libxkbcommon, Xvfb) might be missing. Attempt to install them? (y/N): " choice
         case "$choice" in
           y|Y ) install_egui_deps_debian;;
           * ) echo "Skipping system dependency installation. Build or runtime might fail if they are missing.";;
         esac
    else
        echo "Key GUI development packages (libgtk-3-dev, libxkbcommon-x11-0) found, assuming most dependencies are met."
    fi
else
    echo "Non-Debian-like system detected (or OS could not be determined). Skipping automatic system dependency installation."
    echo "Please ensure you have the necessary development libraries for Egui (e.g., X11, GTK3, dbus, fontconfig, libxkbcommon)."
fi

# 4. Build the Rust application (Release mode)
echo "Building the Rust application ($APP_NAME)..."
cargo build --release --manifest-path "${PROJECT_DIR}/Cargo.toml"

# 5. Run the Rust application
BINARY_PATH="${PROJECT_DIR}/${TARGET_DIR}/release/${APP_NAME}"

if [ ! -f "${BINARY_PATH}" ]; then
    echo "Error: Compiled application not found at ${BINARY_PATH}"
    echo "Build might have failed (possibly due to missing system dependencies)."
    exit 1
fi

echo "Running the application from: ${BINARY_PATH}"
# If on Linux and it's a headless CI-like environment, you might still need xvfb-run for graphical apps.
# For local user execution on a desktop, xvfb-run is usually not needed.
if $IS_DEBIAN_LIKE && ! xdpyinfo &> /dev/null && command -v xvfb-run &> /dev/null; then
    echo "No display server detected, attempting to run with xvfb-run..."
    xvfb-run -a "${BINARY_PATH}"
else
    "${BINARY_PATH}"
fi

echo "Application exited."