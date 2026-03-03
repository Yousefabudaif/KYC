/**
 * Tectonic installer script — downloads the correct Tectonic binary
 * for the current platform (Linux for Heroku, Windows for local dev).
 * Runs automatically via npm postinstall.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const TECTONIC_VERSION = '0.15.0';
const BIN_DIR = path.join(__dirname, '..', 'bin');

function getPlatformAsset() {
    const platform = process.platform;
    const arch = process.arch;

    if (platform === 'linux' && arch === 'x64') {
        return {
            name: `tectonic-${TECTONIC_VERSION}-x86_64-unknown-linux-gnu.tar.gz`,
            binary: 'tectonic',
            extract: 'tar'
        };
    } else if (platform === 'win32' && arch === 'x64') {
        return {
            name: `tectonic-${TECTONIC_VERSION}-x86_64-pc-windows-msvc.zip`,
            binary: 'tectonic.exe',
            extract: 'zip'
        };
    } else if (platform === 'darwin') {
        return {
            name: `tectonic-${TECTONIC_VERSION}-x86_64-apple-darwin.tar.gz`,
            binary: 'tectonic',
            extract: 'tar'
        };
    }
    throw new Error(`Unsupported platform: ${platform}-${arch}`);
}

function download(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                download(res.headers.location).then(resolve).catch(reject);
                return;
            }
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}`));
                return;
            }
            const chunks = [];
            res.on('data', (c) => chunks.push(c));
            res.on('end', () => resolve(Buffer.concat(chunks)));
            res.on('error', reject);
        }).on('error', reject);
    });
}

async function main() {
    const asset = getPlatformAsset();
    const binaryPath = path.join(BIN_DIR, asset.binary);

    // Skip if already installed
    if (fs.existsSync(binaryPath)) {
        console.log(`[Tectonic] Already installed at ${binaryPath}`);
        return;
    }

    console.log(`[Tectonic] Installing v${TECTONIC_VERSION} for ${process.platform}-${process.arch}...`);

    // Create bin directory
    if (!fs.existsSync(BIN_DIR)) {
        fs.mkdirSync(BIN_DIR, { recursive: true });
    }

    const url = `https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40${TECTONIC_VERSION}/${asset.name}`;
    console.log(`[Tectonic] Downloading from ${url}`);

    const data = await download(url);
    const tmpFile = path.join(BIN_DIR, asset.name);
    fs.writeFileSync(tmpFile, data);

    // Extract
    if (asset.extract === 'tar') {
        execSync(`tar -xzf "${tmpFile}" -C "${BIN_DIR}"`, { stdio: 'inherit' });
    } else if (asset.extract === 'zip') {
        // On Windows, use PowerShell
        if (process.platform === 'win32') {
            execSync(`powershell -Command "Expand-Archive -Path '${tmpFile}' -DestinationPath '${BIN_DIR}' -Force"`, { stdio: 'inherit' });
        } else {
            execSync(`unzip -o "${tmpFile}" -d "${BIN_DIR}"`, { stdio: 'inherit' });
        }
    }

    // Clean up archive
    fs.unlinkSync(tmpFile);

    // Make executable on Unix
    if (process.platform !== 'win32') {
        fs.chmodSync(binaryPath, 0o755);
    }

    console.log(`[Tectonic] Installed successfully at ${binaryPath}`);
}

main().catch((err) => {
    console.error('[Tectonic] Installation failed:', err.message);
    console.error('[Tectonic] PDF generation will not work without Tectonic.');
    // Don't fail the build — the app can still run without PDF generation
    process.exit(0);
});
