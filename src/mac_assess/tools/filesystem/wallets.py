"""Cryptocurrency wallet and key file discovery.

Cryptocurrency wallets on developer machines represent high-value targets.
Wallet files, seed phrases stored in plaintext, and browser extension wallets
can be drained instantly if discovered by an attacker.

MITRE ATT&CK: T1657 (Financial Theft), T1552.001 (Credentials in Files)
"""

from __future__ import annotations

from langchain_core.tools import tool

from ..base import run_command


@tool
def find_crypto_wallets() -> str:
    """Discover cryptocurrency wallet files, seed phrases, and key material.

    Searches for:
    - Bitcoin Core wallet files (wallet.dat)
    - Ethereum / Go-Ethereum keystore files (~/.ethereum/keystore/)
    - Monero wallet files
    - Solana keypair files (~/.config/solana/id.json)
    - Cosmos / Tendermint key files
    - Generic wallet.dat files in common locations
    - Browser extension wallet data (MetaMask, Coinbase Wallet, Phantom)
      stored in Chrome/Firefox/Brave/Safari extension dirs
    - Mnemonic seed phrase files (files containing 12/24-word BIP39 phrases)
    - Hardware wallet companion app data (Ledger Live, Trezor Suite)
    - Private key files matching hex/base58 patterns

    Returns:
        Discovered wallet files and key material locations.
    """
    sections = []

    # ── Bitcoin Core ──────────────────────────────────────────────────────────
    bitcoin_wallets = run_command(
        "find ~/Library/Application\\ Support/Bitcoin/ "
        "~/.bitcoin/ 2>/dev/null -name 'wallet.dat' 2>/dev/null"
    )
    sections.append(
        "=== Bitcoin Core wallets (wallet.dat) ===\n"
        + (bitcoin_wallets.stdout.strip() or "(none found)")
    )

    # ── Ethereum / go-ethereum keystore ──────────────────────────────────────
    eth_keystore = run_command(
        "find ~/.ethereum/keystore/ "
        "~/Library/Ethereum/keystore/ 2>/dev/null -type f 2>/dev/null | head -20"
    )
    sections.append(
        "=== Ethereum keystore files (~/.ethereum/keystore/) ===\n"
        + (eth_keystore.stdout.strip() or "(none found)")
    )

    # ── Solana keypairs ───────────────────────────────────────────────────────
    solana_keys = run_command(
        "find ~/.config/solana/ -name '*.json' 2>/dev/null | head -10; "
        "ls ~/.config/solana/ 2>/dev/null"
    )
    sections.append(
        "=== Solana keypairs (~/.config/solana/) ===\n"
        + (solana_keys.stdout.strip() or "(none found)")
    )

    # ── Generic wallet.dat files ──────────────────────────────────────────────
    generic_wallets = run_command(
        "find ~ -maxdepth 7 -name 'wallet.dat' -not -path '*/.git/*' "
        "-not -path '*/node_modules/*' 2>/dev/null | head -20"
    )
    if generic_wallets.stdout.strip():
        sections.append(
            "=== Generic wallet.dat files in home directory ===\n"
            + generic_wallets.stdout.strip()
        )

    # ── Monero ────────────────────────────────────────────────────────────────
    monero = run_command(
        "find ~/Library/Application\\ Support/monero-project/ "
        "~/.bitmonero/ 2>/dev/null -type f 2>/dev/null | grep -v '.log' | head -10"
    )
    if monero.stdout.strip():
        sections.append(f"=== Monero wallet files ===\n{monero.stdout.strip()}")

    # ── Cosmos / Tendermint ───────────────────────────────────────────────────
    cosmos = run_command("ls ~/.gaiad/ ~/.osmosisd/ ~/.evmosd/ 2>/dev/null | head -20")
    if cosmos.stdout.strip():
        sections.append(f"=== Cosmos/Tendermint node directories ===\n{cosmos.stdout.strip()}")

    # ── Browser extension wallets ─────────────────────────────────────────────
    # MetaMask stores vault data in the extension's Local Storage
    browser_profiles = {
        "Chrome":  "~/Library/Application Support/Google/Chrome/Default/Local Extension Settings",
        "Brave":   "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Local Extension Settings",
        "Firefox": "~/Library/Application Support/Firefox/Profiles",
    }

    # Known extension IDs for popular wallets
    wallet_extensions = {
        "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask (Chrome/Brave)",
        "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet",
        "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom (Solana)",
        "aholpfdialjgjfhomihkjbmgjidlcdno": "Exodus Web3",
        "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet",
    }

    ext_hits = []
    for browser, base_path in browser_profiles.items():
        for ext_id, wallet_name in wallet_extensions.items():
            check = run_command(f"ls '{base_path}/{ext_id}/' 2>/dev/null")
            if check.stdout.strip():
                ext_hits.append(f"⚠ {wallet_name} found in {browser}")
    if ext_hits:
        sections.append(
            "=== Browser extension wallets detected ===\n"
            + "\n".join(ext_hits)
        )
    else:
        sections.append("=== Browser extension wallets ===\n(none detected)")

    # ── Ledger Live ───────────────────────────────────────────────────────────
    ledger = run_command(
        "ls ~/Library/Application\\ Support/Ledger\\ Live/ 2>/dev/null | head -10"
    )
    if ledger.stdout.strip():
        sections.append(f"=== Ledger Live data ===\n{ledger.stdout.strip()}")

    # ── Trezor Suite ──────────────────────────────────────────────────────────
    trezor = run_command(
        "ls ~/Library/Application\\ Support/trezor-suite/ 2>/dev/null | head -10"
    )
    if trezor.stdout.strip():
        sections.append(f"=== Trezor Suite data ===\n{trezor.stdout.strip()}")

    # ── Key files: raw private keys (PEM/hex) ─────────────────────────────────
    key_files = run_command(
        "find ~ -maxdepth 5 -type f \\( "
        "-name '*.key' -o -name '*.pem' -o -name 'keystore*' "
        "-o -name 'private_key*' -o -name 'privkey*' \\) "
        "-not -path '*/.git/*' -not -path '*/node_modules/*' "
        "-not -path '*/.ssh/*' 2>/dev/null | head -20",
        timeout=15,
    )
    if key_files.stdout.strip():
        sections.append(
            "=== Private key files found (excluding ~/.ssh/) ===\n"
            + key_files.stdout.strip()
        )

    # ── Seed phrase files (12/24 word mnemonic) ───────────────────────────────
    # Look for files containing BIP39-style word lists
    seed_files = run_command(
        "find ~ -maxdepth 5 -type f \\( "
        "-name '*seed*' -o -name '*mnemonic*' -o -name '*phrase*' -o -name '*recovery*' \\) "
        "-not -path '*/.git/*' -not -path '*/node_modules/*' 2>/dev/null | head -10",
        timeout=15,
    )
    if seed_files.stdout.strip():
        sections.append(
            "=== ⚠ Possible seed phrase / recovery files ===\n"
            + seed_files.stdout.strip()
        )

    return "\n\n".join(sections)
