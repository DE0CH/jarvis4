# Jarvis 4 session image, base layer: the tools, harnesses, entrypoint and harness launchers every session machine runs.
# session-image/Dockerfile puts Jarvis 4's machine side (jarvis-machine) on top of it, FROM this image pinned by digest.
# Built by .github/workflows/images.yml (job `base`) only when session-image/base/ changes, pushed to the public
# package ghcr.io/de0ch/jarvis4-session as tag base-sha-<commit>; the pin job moves session-image/Dockerfile's BASE.
# Size: Fly refuses an image that needs more than 8 GiB ON DISK once unpacked (block-rounded, not tar bytes; the
# machine is destroyed before it boots), and the CI checks the final image against 8.0e9. Trim in the same RUN that installs.
# age-plugin-tag: lets sops encrypt to an age1tag1 recipient (a Secure Enclave key); age ships it as source only
FROM golang:1.25-bookworm AS ageplugin
RUN GOBIN=/out go install filippo.io/age/extra/age-plugin-tag@v1.3.2

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git tmux openssl unzip zip jq ripgrep ffmpeg less nano vim \
      python3 python3-pip python3-venv build-essential sudo gnupg procps \
      openssh-client rsync wget age htop sqlite3 file dnsutils iputils-ping librsvg2-bin \
      psmisc lsof iproute2 sshpass pv zstd libzbar0 whois gawk \
      libreoffice-impress libreoffice-writer libreoffice-calc poppler-utils \
      xdotool xclip imagemagick python3-nacl \
 && rm -rf /var/lib/apt/lists/*
# python3-nacl: sealed boxes for GitHub Actions secrets (the REST API's encrypted_value). Not postgresql: it took the
# session image past Fly's unpack limit (lessons/72); the router's tests install it when needed (`apt-get install postgresql`)
# libreoffice-writer/impress/calc + poppler-utils: open and convert Office documents (soffice --convert-to pdf, pdftoppm;
# calc recalculates .xlsx formulas, e.g. YCC expenses/claim_docs.py);
# python-pptx (below) extracts their text.
# xdotool + xclip + imagemagick: drive a plain (non-CDP) Chromium on Xvfb with real X11 input, read text via the clipboard.
# libzbar0 + pyzbar: decode QR codes.
# rclone: cloud drives (iCloud Drive's iclouddrive backend among them)
RUN curl -fsSL https://rclone.org/install.sh | bash
# Node.js 22
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y nodejs && rm -rf /var/lib/apt/lists/*
# kubectl
RUN curl -fsSL -o /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.33.4/bin/linux/amd64/kubectl" \
 && chmod +x /usr/local/bin/kubectl
# cloudflared (quick tunnels: a temporary public https URL to a local port) + versitygw (an S3 gateway on a local dir)
RUN curl -fsSL -o /usr/local/bin/cloudflared "https://github.com/cloudflare/cloudflared/releases/download/2026.10.0/cloudflared-linux-amd64" \
 && chmod +x /usr/local/bin/cloudflared \
 && curl -fsSL "https://github.com/versity/versitygw/releases/download/v1.8.0/versitygw_v1.8.0_Linux_x86_64.tar.gz" \
  | tar xz -C /usr/local/bin --strip-components=1 versitygw_v1.8.0_Linux_x86_64/versitygw
# sops (+ age above): edit/encrypt SOPS secrets
RUN curl -fsSL -o /usr/local/bin/sops "https://github.com/getsops/sops/releases/download/v3.13.3/sops-v3.13.3.linux.amd64" \
 && chmod +x /usr/local/bin/sops
# litestream: restore SQLite replicas
RUN curl -fsSL "https://github.com/benbjohnson/litestream/releases/download/v0.5.17/litestream-0.5.17-linux-x86_64.tar.gz" \
  | tar -xz -C /usr/local/bin litestream && chmod +x /usr/local/bin/litestream
COPY --from=ageplugin /out/age-plugin-tag /usr/local/bin/age-plugin-tag
# Go toolchain: the official release tarball, newest at build time
RUN curl -fsSL "https://go.dev/dl/$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1).linux-amd64.tar.gz" | tar -C /usr/local -xz \
 && ln -s /usr/local/go/bin/go /usr/local/bin/go && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
# kubeseal
RUN curl -fsSL "https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.40.0/kubeseal-0.40.0-linux-amd64.tar.gz" \
    | tar -xzO kubeseal > /usr/local/bin/kubeseal \
 && chmod +x /usr/local/bin/kubeseal
# gh (GitHub CLI): CI runs, PRs, releases; GITHUB_TOKEN auths it
RUN mkdir -p -m 755 /etc/apt/keyrings \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update && apt-get install -y --no-install-recommends gh && rm -rf /var/lib/apt/lists/* \
 && gh --version
# crane: copy/inspect registry images without docker
RUN curl -fsSL "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" \
  | tar -xz -C /usr/local/bin crane
# fastlane (spaceship): App Store Connect / developer-portal steps the public API lacks
RUN apt-get update && apt-get install -y --no-install-recommends ruby-full build-essential && rm -rf /var/lib/apt/lists/* \
 && gem install fastlane -N && fastlane --version >/dev/null
# yt-dlp
RUN curl -fsSL -o /usr/local/bin/yt-dlp "https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp" \
 && chmod +x /usr/local/bin/yt-dlp
# typst
RUN curl -fsSL -o /tmp/typst.tar.xz "https://github.com/typst/typst/releases/download/v0.15.1/typst-x86_64-unknown-linux-musl.tar.xz" \
 && tar -xJf /tmp/typst.tar.xz -C /tmp \
 && install -m 755 /tmp/typst-x86_64-unknown-linux-musl/typst /usr/local/bin/typst \
 && rm -rf /tmp/typst.tar.xz /tmp/typst-x86_64-unknown-linux-musl \
 && typst --version
# flyctl
RUN curl -fsSL https://fly.io/install.sh | FLYCTL_INSTALL=/usr/local sh \
 && test -x /usr/local/bin/flyctl
# hcloud: Hetzner Cloud CLI
RUN curl -fsSL https://github.com/hetznercloud/cli/releases/download/v1.70.1/hcloud-linux-amd64.tar.gz \
  | tar -xz -C /usr/local/bin hcloud && hcloud version
# Tailscale CLI + daemon (run tailscaled with --tun=userspace-networking inside the microVM)
RUN curl -fsSL https://tailscale.com/install.sh | sh
# Every `npm install -g` ends with `npm cache clean --force` in the SAME RUN: npm keeps a copy of each
# tarball in /root/.npm, and that cache was 1.06 GB of the image.
# vercel CLI
RUN npm install -g vercel && npm cache clean --force
# wrangler: Cloudflare Workers
RUN npm install -g wrangler && npm cache clean --force
# Tencent CloudBase CLI (`tcb`)
RUN npm install -g @cloudbase/cli@3 && npm cache clean --force
# browse: the Browserbase CLI; needs BROWSERBASE_API_KEY at runtime
RUN npm install -g browse && npm cache clean --force
# Common Python libs (Ubuntu 24.04's pip is externally managed): HTTP and HTML, PDF (pymupdf), Office files,
# TOTP (pyotp), images (pillow, numpy, QR codes), browser-grade TLS (curl_cffi), SOCKS and a local no-auth proxy
# forwarder (pproxy), cloud SDKs (boto3, Aliyun core), Hugging Face, charts, Microsoft OAuth (msal), a KTX API client.
RUN pip3 install --no-cache-dir --break-system-packages \
      requests beautifulsoup4 lxml pymupdf python-docx pyotp pillow boto3 \
      telethon PySocks python-socks python-pptx pyzbar curl_cffi eth-account pproxy websocket-client \
      zxing-cpp "qrcode[pil]" numpy aliyun-python-sdk-core pyyaml huggingface_hub gradio_client matplotlib msal korail-mobile-api
# mihomo (the Clash Meta core): test proxy subscriptions end to end
RUN curl -fsSL https://github.com/MetaCubeX/mihomo/releases/download/v1.19.31/mihomo-linux-amd64-v1.19.31.gz \
      | gunzip > /usr/local/bin/mihomo && chmod 755 /usr/local/bin/mihomo && mihomo -v
# Browser tooling. Playwright for Node is GLOBAL (scripts `require('playwright')` via NODE_PATH); the Python
# package is pinned to the same version so both share ONE Chromium build under /opt/pw-browsers.
# WebKit too, so pages can be checked in Safari's engine (iPhone behaviour) without a Mac.
# `--with-deps` pulls the browsers' system libs; CJK fonts so Chinese pages render in screenshots; `ws` for
# WebSocket helpers; edge-tts for voice-over. Stable symlinks (/opt/pw-browsers/chromium, /opt/pw-browsers/headless_shell)
# hide the revision-numbered dirs, and the build FAILS if either binary isn't where expected.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH=/usr/lib/node_modules
RUN npm install -g playwright@1.62.0 ws && npm cache clean --force \
 && playwright install --with-deps chromium chromium-headless-shell webkit \
 && pip3 install --no-cache-dir --break-system-packages playwright==1.62.0 edge-tts tronpy pyotp \
 && apt-get update && apt-get install -y --no-install-recommends fonts-noto-cjk fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s "$(find /opt/pw-browsers -path '*/chromium-*' -type f -name chrome | head -1)" /opt/pw-browsers/chromium \
 && ln -s "$(find /opt/pw-browsers -path '*/chromium_headless_shell-*' -type f \( -name headless_shell -o -name chrome-headless-shell \) | head -1)" /opt/pw-browsers/headless_shell \
 && test -x /opt/pw-browsers/chromium && test -x /opt/pw-browsers/headless_shell \
 && test -n "$(find /opt/pw-browsers -maxdepth 1 -name 'webkit-*')" \
 && ln -s /opt/pw-browsers/chromium /usr/local/bin/chromium \
 && chmod -R a+rX /opt/pw-browsers
# Real Google Chrome stable (`google-chrome`) next to Playwright's Chromium: some anti-bot layers reject "Chrome for Testing".
RUN wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
 && apt-get update && apt-get install -y --no-install-recommends xdg-utils /tmp/chrome.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/chrome.deb \
 && google-chrome --version
# Git identity + GitHub auth for every session: commits as `claude <claude@selfhost>`; pushes read $GITHUB_TOKEN from
# the environment at call time (nothing sensitive lands in .git/config).
RUN git config --system user.name claude \
 && git config --system user.email claude@selfhost \
 && git config --system credential.https://github.com.helper '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'
# Non-root user with passwordless sudo. claude refuses --dangerously-skip-permissions
# as root, and per-session tool installs want sudo.
RUN useradd -m -s /bin/bash claude \
 && echo 'claude ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-claude \
 && chmod 0440 /etc/sudoers.d/90-claude
# iOS device control over a network link: wireguard-tools, and pymobiledevice3 in its own Python 3.13 venv via uv
# (iOS 18.2+ tunnels are TCP-only and need 3.13+). No pairing record is in the image.
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools && rm -rf /var/lib/apt/lists/* \
 && curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
 && UV_PYTHON_INSTALL_DIR=/opt/uv-python uv venv --python 3.13 /opt/ios \
 && uv pip install --no-cache --python /opt/ios/bin/python pymobiledevice3==11.19.4
# VNC screenshots (asyncvnc), Camoufox with the GTK libs its Firefox build needs, xdotool/xclip for X windows.
# rapidocr_onnxruntime: offline Chinese OCR.
RUN pip3 install --no-cache-dir --break-system-packages rapidocr_onnxruntime
RUN pip3 install --no-cache-dir --break-system-packages asyncvnc "camoufox[geoip]" \
 && apt-get update && apt-get install -y --no-install-recommends libgtk-3-0t64 libdbus-glib-1-2 libasound2t64 libx11-xcb1 xdotool xclip \
 && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY harness-claude.sh /usr/local/bin/harness-claude.sh
COPY workspace-layer.sh /usr/local/bin/workspace-layer.sh
COPY pull-secrets /usr/local/bin/pull-secrets
COPY session-secret /usr/local/bin/session-secret
COPY content-sync /usr/local/bin/content-sync
COPY set-permission-mode /usr/local/bin/set-permission-mode
# The OpenRouter harness (an OpenRouter model): OpenCode is the agent, the Paseo daemon drives it and is the
# remote control (its app over its relay + a web UI published through the cf-tunnel agent, cf-tunnel-agent.js).
# harness-opencode.sh is its launcher; `ws` is global.
# Size: trim in the SAME layer: opencode runs bin/opencode.exe, a copy of its platform package (both platform packages
# = 2 x 185 MB more), and Paseo's bundled Claude Agent SDK binary (248 MB) becomes a link to the image's own claude.
RUN npm install -g opencode-ai@1.18.31 @getpaseo/cli@0.8.0 && npm cache clean --force \
 && rm -rf /usr/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64 /usr/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64-baseline \
 && opencode --version \
 && f=/usr/lib/node_modules/@getpaseo/cli/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64/claude \
 && rm -f "$f" && ln -s /home/claude/.local/bin/claude "$f"
COPY harness-opencode.sh /usr/local/bin/harness-opencode.sh
# Claude Code · Paseo (harness paseo-claude): the same daemon drives the image's own claude through that SDK link,
# behind api-proxy.js (the session's current Claude login per request).
COPY harness-paseo-claude.sh /usr/local/bin/harness-paseo-claude.sh
COPY opencode-instructions.py /usr/local/bin/opencode-instructions.py
COPY harness-send /usr/local/bin/harness-send
COPY session-attachments /usr/local/bin/session-attachments
COPY opencode-transcript.py /usr/local/bin/opencode-transcript.py
COPY paseo-front.js /usr/local/lib/paseo-front.js
COPY api-proxy.js /usr/local/lib/api-proxy.js
COPY cf-tunnel-agent.js /usr/local/lib/cf-tunnel-agent.js
RUN chmod +x /usr/local/bin/harness-opencode.sh /usr/local/bin/harness-paseo-claude.sh /usr/local/bin/harness-send /usr/local/bin/session-attachments /usr/local/bin/opencode-transcript.py /usr/local/bin/opencode-instructions.py
# The claw-code harness (a "claw-code · OpenClaw" model): claw-code (DE0CH/claw-code) is the agent loop, an OpenClaw
# gateway (DE0CH/openclaw) the front end. claw (~20 MB) is baked in from the release pinned in forks.json, checked by
# sha256 (.github/workflows/fork-pin.yml writes the pin). OpenClaw + its Node 26 (~900 MB) are NOT in the image:
# session-image/Dockerfile adds /usr/local/bin/openclaw, which fetches the runtime bundle pinned by sha256 in
# session-image/openclaw-runtime.json on first use.
COPY forks.json /usr/local/share/forks.json
RUN url="$(python3 -c 'import json;print(json.load(open("/usr/local/share/forks.json"))["claw"]["url"])')" \
 && sum="$(python3 -c 'import json;print(json.load(open("/usr/local/share/forks.json"))["claw"]["sha256"])')" \
 && curl -fsSL -o /usr/local/bin/claw "$url" && echo "$sum  /usr/local/bin/claw" | sha256sum -c - \
 && chmod +x /usr/local/bin/claw && /usr/local/bin/claw --version
COPY openclaw-claw-harness /usr/local/lib/openclaw-claw-harness
COPY harness-openclaw.sh /usr/local/bin/harness-openclaw.sh
COPY openclaw-transcript /usr/local/bin/openclaw-transcript
RUN chmod +x /usr/local/bin/harness-openclaw.sh /usr/local/bin/openclaw-transcript
# Claude Code · CloudCLI (harness cloudcli): Deyao's CloudCLI fork (DE0CH/claudecodeui) drives the image's own claude,
# behind api-proxy.js; the Jarvis 4 Chat app and the web UI are its front end. The fork, its Node and a portable
# PostgreSQL are NOT in the image: session-image/Dockerfile adds /usr/local/bin/cloudcli-runtime, which fetches the
# runtime bundle pinned by sha256 in session-image/cloudcli-runtime.json on first use.
COPY harness-cloudcli.sh /usr/local/bin/harness-cloudcli.sh
RUN chmod +x /usr/local/bin/harness-cloudcli.sh
# DeepSeek Harness (harness dsh): Deyao's fork DE0CH/deepseek-harness serves its agent loop and web UI on the session;
# OpenRouter routed to DeepSeek's own endpoint. The fork and its Node (24) are NOT in the image: session-image/Dockerfile
# adds /usr/local/bin/dsh-runtime, which fetches the bundle pinned by sha256 in session-image/dsh-runtime.json on first
# use. dsh-profile-patch.py feeds it the workspace CLAUDE.md (@imports) and the Claude Code skill roots.
COPY harness-dsh.sh /usr/local/bin/harness-dsh.sh
COPY dsh-profile-patch.py dsh-transcript.py dsh-send.py /usr/local/bin/
COPY dsh-front.js /usr/local/lib/dsh-front.js
RUN chmod +x /usr/local/bin/harness-dsh.sh /usr/local/bin/dsh-profile-patch.py /usr/local/bin/dsh-transcript.py /usr/local/bin/dsh-send.py
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/harness-claude.sh /usr/local/bin/workspace-layer.sh /usr/local/bin/pull-secrets /usr/local/bin/session-secret /usr/local/bin/content-sync /usr/local/bin/set-permission-mode
USER claude
WORKDIR /home/claude
# Native claude binary for the claude user.
# Bump CLAUDE_REFRESH to bust the Docker cache and reinstall the LATEST CLI on rebuild
# (the install.sh RUN is otherwise cached, so the CLI would never update).
ARG CLAUDE_REFRESH=2026-09-23b
RUN echo "claude cli refresh ${CLAUDE_REFRESH}" && curl -fsSL https://claude.ai/install.sh | bash && ~/.local/bin/claude --version
ENV PATH=/home/claude/.local/bin:/usr/local/bin:/usr/bin:/bin
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
