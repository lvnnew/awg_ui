# Amnezia Web Panel

A modern, high-performance web interface for managing **AmneziaWG**, **Classic WireGuard**, **Xray (XTLS-Reality)**, **Telemt (Telegram MTProxy)**, **AmneziaDNS**, **AdGuard Home** and **SOCKS5** services on remote Ubuntu servers — from a single dashboard. Designed to provide a premium user experience with robust administrative capabilities.

> ### 🍴 About this fork
>
> This is a fork of [PRVTPRO/Amnezia-Web-Panel](https://github.com/PRVTPRO/Amnezia-Web-Panel) focused on **self-service VPN for a circle of friends**. On top of the original panel it adds:
>
> *   **Self-registration via the Telegram bot using invite codes** — you hand a friend a code, they register themselves in the bot and create their own configs (per server / protocol / device) without any admin action.
> *   **Invite-code management** — create/list/revoke codes from the web panel (`/settings`) or from the bot (`/newcode`).
> *   **Reworked bot UX** — guided "new device" flow, "My configs", live **server status (ping)**, a **/help** guide, and a welcome message with the house rules.
> *   **Telemt over a domain** — connection links can use your own domain instead of a bare IP, and the bot now emits a working **FakeTLS** `tg://proxy` link plus a one-tap **Apply** button.
> *   **Hardened AWG install** — fresh AmneziaWG installs match the official Amnezia-app layout (`wg0.conf`, `amnezia-wg` image, no `S3/S4` in the client config) for correct connectivity on **iPhone/macOS**.
> *   **Container image on GHCR + Kubernetes manifests** — see [Deployment](#-deployment).
>
> See [Self-Service via Telegram Bot](#-self-service-via-telegram-bot) for the end-to-end workflow.

> ### 🔄 Compatibility with Official Amnezia Client
> 
> This panel is fully compatible with the official **Amnezia** applications!
> 
> **How to connect an existing server:**
> 1. Add your pre-configured server by entering its **IP address**, **login** and **password**
> 2. Go to the "Added Servers" section
> 3. Wait for the automatic server verification
> 4. The panel will automatically detect:
>    - ✅ Installed protocols
>    - ✅ Existing users
>    - ✅ Current configuration
>
> ⚡ **After verification, you can manage the server directly from the panel!**

## ⚠️ Legal Notice

> **This project is created solely for educational and research purposes.**
>
> **This project has never been intended for use in jurisdictions where the technologies employed are prohibited.** The author bears no responsibility for any unlawful use of this software.

**This project merely adds an abstraction layer for managing publicly available applications.** All applications belong to their respective owners. This project does not claim ownership over, nor does it modify, any third-party applications.

The use of traffic obfuscation tools may violate the laws of your country. Only use this software for lawful purposes, such as:

- **Penetration testing and security research**
- **CTF (Capture The Flag) competitions**
- **Academic and scientific research**
- **Testing and securing your own networks**
- **Improving defensive security measures**
- **Educational training in cybersecurity**

> **Nothing in this project constitutes an incitement to violate any applicable laws.**
![Servers Dashboard](https://raw.githubusercontent.com/PRVTPRO/Amnezia-Web-Panel/refs/heads/main/screen/panel1.png)


### Additional Sections

<details>
<summary><b>👥 Users Management</b> (click to expand)</summary>
<br>
User management interface with permissions and access controls:

![Users Management](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-2.png)
</details>

<details>
<summary><b>⚙️ System Settings</b> (click to expand)</summary>
<br>
Configuration panel for system parameters and preferences:

![Settings Panel](https://github.com/PRVTPRO/Amnezia-Web-Panel/blob/main/screen/panel1-3.png)
</details>

## 🚀 Key Features

*   **⚡ VPN Protocols**:
    *   **AmneziaWG (AWG / AWG 2.0 / AWG Legacy)**: Advanced WireGuard-based protocol with S3/S4 obfuscation to bypass deep packet inspection (DPI). Three coexisting variants — modern AWG 2.0 with full junk-packet masking, and a legacy variant for older clients.
    *   **Classic WireGuard**: Standard, high-performance WireGuard protocol for unmatched speed and broad device compatibility with traffic monitoring support.
    *   **Xray (XTLS-Reality)**: Stealthy protocol that masks VPN traffic as standard HTTPS browsing. Pinned to **Xray-core v26.x**; transparently reads both the **panel layout** (`meta.json` + `clientsTable.json`) and the **native Amnezia client layout** (`xray_*.key` files + `clientsTable`), so a node first installed via the official mobile/desktop app can be attached to the panel without re-installation.
    *   **Telemt (Telegram MTProxy)**: High-performance Telegram MTProxy with TLS emulation and comprehensive management (quotas, IP limits, real-time session tracking). Robust install path that auto-configures Docker's official apt/yum repository when needed.
*   **🛠 Services**:
    *   **AmneziaDNS**: Internal DNS resolver on a private docker network (`amnezia-dns-net`, IP `172.29.172.254`) to prevent DNS leaks and blockings.
    *   **AdGuard Home** *(new)*: DNS-based ad blocker with a web admin UI. Two install modes: **Replace AmneziaDNS** (takes its IP, all VPN clients use AdGuard immediately) or **Side-by-side** (parallel deployment on `172.29.172.253`, web UI accessible only over the VPN by default). Optional opt-in checkboxes to expose the web UI / DoT / DoH on the host.
    *   **SOCKS5 Proxy** *(new)*: Single-account 3proxy-based SOCKS5 server modelled after the official Amnezia client. Auto-generated 16-character password on install, port and credentials editable later from the panel without re-install.
*   **⚙️ Core Server Management**:
    *   **Add / Edit / Delete / Reorder** server entries — drag-and-drop reorder updates `server_id` references in saved connections automatically.
    *   **Live ping indicator** next to each server name — non-blocking TCP-connect probe to the SSH port, runs on the asyncio loop in parallel for all servers.
    *   **Clear server** wipes every Amnezia-related container, image and `/opt/amnezia` directory in a single sudo script — works for any current or future `amnezia-*` protocol.
    *   **Reboot** the server directly from the UI.
    *   Strictly concurrent protocol status polling — all 9 protocols/services checked in parallel for immediate feedback.
    *   **Asynchronous Processing**: Resilient, non-blocking background architecture prevents the UI panel from freezing, even if remote endpoints hang.
*   **🌐 Internationalization (i18n)**:
    *   Full support for **English**, **Russian**, **French**, **Chinese**, and **Persian**.
    *   Native **RTL (Right-to-Left)** support for Persian language.
*   **👥 Advanced User Management**:
    *   Role-based access (Admin, Support, Regular User).
    *   Traffic limits, status monitoring, and account expiration.
    *   One-click user enabling/disabling.
*   **🎨 Premium UI/UX**:
    *   Stunning glassmorphism design.
    *   Dynamic **Dark/Light** mode transition.
    *   Fully responsive for mobile and desktop.
*   **🤖 Telegram Bot — Self-Service** *(fork)*:
    *   **Self-registration by invite code** — a friend sends `/start`, enters the code you gave them, and is registered automatically.
    *   **Per-device config creation** — guided flow: pick **server → protocol → device name** (or auto-generated unique name). One config = one device.
    *   **My configs / Server status / Help** buttons, plus commands `/start`, `/menu`, `/help`, and admin-only `/newcode`.
    *   **Telegram proxy (Telemt)** configs ship with a one-tap **Apply** button (`https://t.me/proxy?...`) and a copyable link.
*   **🔄 Built-in Update Checker**:
    *   View your current panel version directly in Settings.
    *   One-click check for fresh GitHub releases to stay up to date.
*   **📤 Data Interoperability**:
    *   **Remnawave Sync**: Automatically import and sync users from Remnawave.
    *   **Simple Backup**: Effortless JSON-based export and restore of all panel data.
*   **🔗 Public Sharing**:
    *   Generate password-protected links for users to download their configurations without panel access.
*   **🔑 API Tokens for External Integrations** *(new)*:
    *   Issue bearer tokens from `/settings` for CI bots, monitoring, or any third-party service.
    *   Panel never stores the raw token — only its SHA-256 hash. The full value is shown **once** at creation; lose it and you must rotate.
    *   Tokens inherit the role of the admin who created them and are revoked automatically if that user is disabled or demoted.
    *   Send `Authorization: Bearer <token>` with any admin endpoint — every endpoint that accepts a session also accepts a token, no other changes.

## 🤝 Self-Service via Telegram Bot

This fork lets your friends provision their own VPN configs without you touching the panel each time.

**One-time setup (admin):**

1. In the panel open **Settings → Telegram**, paste your bot token (from [@BotFather](https://t.me/BotFather)) and **enable** the bot, then **Save**.
2. Make sure your own account is an **admin** panel user with your numeric Telegram ID set — admins get the `/newcode` command and the in-bot code generator.

**Issuing invite codes:**

*   From the panel: **Settings → Invite Codes** — create one or many codes, set how many times each can be used, copy and share.
*   From the bot (admin): `/newcode [count] [max_uses]` — e.g. `/newcode 5 1` makes 5 single-use codes.

**Friend's flow:**

1. Open the bot → `/start`.
2. Send the **invite code** (or `/register CODE`).
3. Use **➕ New device / config** → choose **server → protocol → device name**.
4. Receive the config:
    *   **AmneziaWG / WireGuard** — a `.conf` file in the *Original AmneziaWG format* (works on iPhone, macOS, Android, Windows). Import it into the **AmneziaVPN** or **AmneziaWG** app.
    *   **Telemt (Telegram proxy)** — tap **✅ Apply** to open Telegram's native "Connect proxy?" dialog, or copy the `tg://proxy?...` link.

**House rules surfaced to users** (welcome + `/help`):

*   👤 **One user — one access code.** Codes are personal and consumed on use.
*   📱 **One config — one device.** Create a separate config per phone/laptop; don't share configs.

### Telemt over your own domain

By default the proxy link uses the server IP. To use a domain instead:

1. Create a DNS **A record** pointing your domain to the server IP (e.g. `proxy.example.com → 1.2.3.4`).
2. Either set the **domain field** when installing Telemt, or click the **🌐** button on the installed Telemt card to change it without reinstalling (existing users are preserved).
3. The bot then emits a FakeTLS link of the form
   `tg://proxy?server=<domain>&port=443&secret=ee<secret><hex(tls_domain)>`.

## 💡 Need Additional Functionality?

If you require any custom features not currently available in the panel, **let us know – we'll implement them quickly!** 

* **Database Support**: PostgreSQL, MySQL/MariaDB, SQLite, Oracle, and MS SQL Server
* **In-Panel File Editor**: Edit configuration files inside containers directly from the web interface
* **Backup & Restore nodes/protocols**: Comprehensive backup solutions for nodes and protocols
* **Protocol Migration**: Seamlessly move protocols between nodes
* **Xray Self-Steal Mode**: Advanced Xray configuration with self-steal functionality
* **And much more!**

**Or better yet, contribute!**


## 🏗 Prerequisites

*   **Python 3.10+**
*   Target servers: **Ubuntu 20.04/22.04/24.04** (Architecture: x86_64 or ARM64).
*   SSH access to target servers (Password or Private Key).

## 📦 Installation 

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/PRVTPRO/Amnezia-Web-Panel.git
    cd Amnezia-Web-Panel
    ```

2.  **Set up Virtual Environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
## 🚀 Getting Started

Launch the application:

```bash
python app.py
```

The panel will be accessible at `http://localhost:5000`.

## 📦 Installation Method 2

Download and run the executable file for your system.
```
Windows
Linux
Mac
```

## 🐳 Docker Image

Upstream image: https://hub.docker.com/r/prvtpro/amnezia-panel

## 🚢 Deployment

This fork ships a **GitHub Actions** workflow (`.github/workflows/docker-image.yml`) that builds and pushes a container image to **GitHub Container Registry (GHCR)** on every push to `main` and on `v*` tags. The image is tagged with `latest`, the git tag, and a short SHA (`sha-<commit>`), so you can pin deployments to an exact commit.

**Image:** `ghcr.io/<your-gh-user>/<repo>` (e.g. `ghcr.io/lvnnew/awg_ui:latest`).

### Run with Docker

```bash
docker run -d --name amnezia-panel \
  -p 5000:5000 \
  -v $(pwd)/data.json:/app/data.json \
  -e SECRET_KEY="change-me" \
  ghcr.io/<your-gh-user>/<repo>:latest
```

Mount `data.json` (or a volume) so panel state — servers, users, invite codes, settings — survives restarts.

### Run on Kubernetes

Minimal example (Deployment + Service + a PVC for `data.json`):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: amnezia-panel
  namespace: awg-panel
spec:
  replicas: 1
  selector:
    matchLabels: { app: amnezia-panel }
  template:
    metadata:
      labels: { app: amnezia-panel }
    spec:
      containers:
        - name: amnezia-panel
          image: ghcr.io/<your-gh-user>/<repo>:latest
          ports: [{ containerPort: 5000 }]
          env:
            - name: SECRET_KEY
              valueFrom: { secretKeyRef: { name: amnezia-panel-env, key: SECRET_KEY } }
          volumeMounts:
            - name: data
              mountPath: /app/data.json
              subPath: data.json
      volumes:
        - name: data
          persistentVolumeClaim: { claimName: amnezia-panel-data }
---
apiVersion: v1
kind: Service
metadata:
  name: amnezia-panel
  namespace: awg-panel
spec:
  selector: { app: amnezia-panel }
  ports: [{ port: 80, targetPort: 5000 }]
```

> **Note:** mount `data.json` with `subPath` (as above) so the panel writes to a persistent file rather than an ephemeral container path. Expose the Service via your Ingress controller and put TLS in front (see Security Recommendations).

### Initial Login
*   **Username**: `admin`
*   **Password**: `admin`
> [!IMPORTANT]  
> Secure your panel by changing the default password in the **Users** section immediately after first login.

## 🔧 Project Details

### API Documentation

The project includes self-documenting API endpoints, organised into clear tag groups:

*   **Swagger UI**: `/docs`
*   **ReDoc**: `/redoc` (pinned to a stable bundle, Google Fonts disabled — works on networks where they're blocked)

Routes are grouped in the docs as:

| Group | Purpose |
| --- | --- |
| **System Templates** | HTML pages served to browsers (login, server detail, settings, /share). Not part of the JSON API. |
| **Authentication** | Login, captcha, session lifecycle. |
| **Servers** | Server inventory & host-level operations (add/edit/delete, ping, reorder, reboot, clear, stats). |
| **Protocols** | Install / uninstall / container / raw-config editing for every protocol & service on a server. |
| **Connections** | Per-protocol VPN client connections (CRUD, enable/disable, fetch config). |
| **Users** | Panel user accounts and the connections assigned to them. |
| **Self-service** | Endpoints called by a regular user for their own data (`/api/my/*`). |
| **Sharing** | Public, token-protected configuration sharing — no panel session required. |
| **Settings** | Panel-wide settings, Telegram bot, Remnawave sync, JSON backup/restore. |
| **Invite Codes** | Create / list / revoke self-registration codes used by friends in the Telegram bot. |
| **API Tokens** | Create and revoke bearer tokens for external integrations. |

**Authentication for external integrations** — both session cookies and `Authorization: Bearer <token>` are accepted on every admin endpoint. Example:

```bash
TOKEN="awp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# List panel users
curl -H "Authorization: Bearer $TOKEN" http://your-panel:5000/api/users

# Add a server
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"host":"1.2.3.4","username":"root","password":"...","name":"new-srv"}' \
  http://your-panel:5000/api/servers/add

# Cheap reachability probe for monitoring
curl -H "Authorization: Bearer $TOKEN" http://your-panel:5000/api/servers/0/ping
```

### Technology Stack
*   **Backend**: FastAPI (Python), `asyncio` for concurrent SSH/probe work
*   **Frontend**: Vanilla JS, Jinja2, Custom CSS (Glassmorphism, full set of CSS animations for promo blocks)
*   **Database**: Local JSON storage (`data.json`) with an `asyncio.Lock` for thread-safe writes
*   **SSH Engine**: Paramiko

### Project Structure

```
web-panel/
├── app.py                    # FastAPI entry point + all routes (incl. invite codes & bot services)
├── telegram_bot.py           # Telegram bot: self-registration, device flow, status, help
├── managers/                 # Protocol & service managers (one file per protocol)
│   ├── ssh_manager.py        # SSH abstraction (Paramiko wrapper)
│   ├── awg_manager.py        # AmneziaWG / AWG 2.0 / AWG Legacy (auto-detects wg0/awg0 layout)
│   ├── wireguard_manager.py  # Classic WireGuard
│   ├── xray_manager.py       # Xray-core (VLESS-Reality)
│   ├── telemt_manager.py     # Telegram MTProxy (domain/public_host, local FakeTLS link)
│   ├── dns_manager.py        # AmneziaDNS (Unbound)
│   ├── adguard_manager.py    # AdGuard Home
│   └── socks5_manager.py     # 3proxy-based SOCKS5
├── protocol_telemt/          # Telemt assets (config.toml, docker-compose.yml, Dockerfile)
├── static/                   # CSS / favicon / vendored JS
├── templates/                # Jinja2 templates (incl. invite-codes UI in settings.html)
├── translations/             # en / ru / fr / zh / fa
├── .github/workflows/        # CI: build & push image to GHCR
└── data.json                 # Panel state (servers, users, invite codes, tokens, settings)
```

## 🛡 Security Recommendations

*   **Reverse Proxy**: It is highly recommended to run the panel behind Nginx/Apache with an SSL certificate.
*   **SSH Keys**: Use SSH keys rather than passwords for connecting to your VPN servers.
*   **Secret Key**: Set a custom `SECRET_KEY` environment variable for secure session management.
*   **API Tokens**: Treat each token like a password — store it in your integration's secret manager. Revoke it from `/settings` if it leaks or the integration is decommissioned. Rotate periodically; tokens inherit admin rights.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit Pull Requests or open Issues for feature requests and bug reports.

## 📄 License

This project is licensed under the **GNU General Public License v3.0** - see the [LICENSE](../LICENSE) file for details.


---
*Built with ❤️ for the Amnezia community.*
