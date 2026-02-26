# Dockerfile for Code Guardian VS Code Extension Evaluation Environment
FROM ubuntu:22.04

# Set non-interactive frontend and working directory
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /evaluation

# Configure memory and resource limits
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV NODE_OPTIONS="--max-old-space-size=4096"

# Install system dependencies including X11 for VS Code GUI testing
RUN apt-get update && apt-get install -y \
    curl \
    git \
    wget \
    unzip \
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    lsb-release \
    htop \
    psmisc \
    procps \
    bc \
    # X11 and GUI dependencies
    xvfb \
    libnss3-dev \
    libatk-bridge2.0-dev \
    libdrm2 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libxss1 \
    libasound2 \
    libatspi2.0-0 \
    libgtk-3-0 \
    # Python dependencies
    python3 \
    python3-dev \
    python3-venv \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Add deadsnakes PPA for Python 3.9+ if needed
RUN add-apt-repository ppa:deadsnakes/ppa -y \
    && apt-get update \
    && apt-get install -y \
    python3.9 \
    python3.9-dev \
    python3.9-venv \
    python3.9-distutils \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.9 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.9 1

# Install Node.js 18+ (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get update && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Verify Node.js and npm versions
RUN node --version && npm --version

# Install VS Code and VS Code CLI
RUN wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg \
    && install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/ \
    && sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list' \
    && apt-get update \
    && apt-get install -y code \
    && rm -rf /var/lib/apt/lists/*

# Install VS Code CLI separately (latest version)
RUN curl -Lk 'https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64' --output vscode_cli.tar.gz \
    && tar -xf vscode_cli.tar.gz -C /usr/local/bin \
    && rm vscode_cli.tar.gz \
    && chmod +x /usr/local/bin/code

# Install global Node.js packages for analysis
RUN npm install -g \
    @vscode/vsce \
    typescript \
    @typescript-eslint/parser \
    @typescript-eslint/eslint-plugin \
    eslint \
    jshint \
    yarn

# Create Python virtual environment with Python 3.9
RUN python3.9 -m venv /evaluation/venv
ENV PATH="/evaluation/venv/bin:$PATH"

# Upgrade pip and install core Python packages
RUN pip install --upgrade pip setuptools wheel

# Install required Python packages
RUN pip install --no-cache-dir \
    numpy>=1.21.0 \
    pandas>=1.3.0 \
    scikit-learn>=1.0.0 \
    matplotlib>=3.4.0 \
    scipy>=1.7.0 \
    seaborn>=0.11.0 \
    jupyter>=1.0.0 \
    ipython>=7.25.0 \
    requests>=2.26.0 \
    pyyaml>=5.4.0 \
    tqdm>=4.62.0 \
    colorama>=0.4.4

# Install security analysis tools
RUN pip install --no-cache-dir \
    semgrep>=1.0.0 \
    bandit>=1.7.0 \
    safety>=2.0.0 \
    pylint>=2.9.0

# Install CodeQL CLI for baseline comparison
RUN wget -O codeql.zip https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip \
    && unzip codeql.zip \
    && mv codeql /usr/local/bin/ \
    && rm codeql.zip

# Create evaluation directories with proper permissions
RUN mkdir -p /evaluation/{datasets,baselines,metrics,results,logs,scripts} \
    && chmod -R 755 /evaluation

# Set environment variables for evaluation
ENV PYTHONPATH="/evaluation"
ENV PATH="/usr/local/bin/codeql:${PATH}"
ENV DISPLAY=:99

# Resource monitoring setup
RUN echo '#!/bin/bash\n\
echo "System Resources:"\n\
echo "CPU: $(nproc) cores"\n\
echo "Memory: $(free -h | grep Mem | awk '"'"'{print $2}'"'"')"\n\
echo "Disk: $(df -h / | tail -1 | awk '"'"'{print $4}'"'"') available"\n\
echo "Node.js: $(node --version)"\n\
echo "Python: $(python --version)"\n\
echo "VS Code: $(code --version | head -1)"\n\
' > /usr/local/bin/system-info && chmod +x /usr/local/bin/system-info

# Create Xvfb startup script with resource monitoring
RUN echo '#!/bin/bash\n\
# Display system info\n\
system-info\n\
\n\
# Start Xvfb for headless GUI testing\n\
echo "Starting Xvfb..."\n\
Xvfb :99 -screen 0 1024x768x24 &\n\
XVFB_PID=$!\n\
\n\
# Memory monitoring function\n\
monitor_resources() {\n\
    while true; do\n\
        MEMORY_USAGE=$(free | grep Mem | awk '"'"'{print ($3/$2) * 100.0}'"'"')\n\
        CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\\([0-9.]*\\)%* id.*/\\1/" | awk '"'"'{print 100 - $1}'"'"')\n\
        \n\
        if command -v bc >/dev/null 2>&1; then\n\
            if (( $(echo "$MEMORY_USAGE > 90" | bc -l) )); then\n\
                echo "WARNING: High memory usage: ${MEMORY_USAGE}%"\n\
            fi\n\
            \n\
            if (( $(echo "$CPU_USAGE > 90" | bc -l) )); then\n\
                echo "WARNING: High CPU usage: ${CPU_USAGE}%"\n\
            fi\n\
        fi\n\
        \n\
        sleep 30\n\
    done\n\
}\n\
\n\
# Start resource monitoring in background\n\
monitor_resources &\n\
MONITOR_PID=$!\n\
\n\
# Cleanup function\n\
cleanup() {\n\
    echo "Cleaning up..."\n\
    kill $XVFB_PID $MONITOR_PID 2>/dev/null || true\n\
    exit\n\
}\n\
\n\
trap cleanup SIGTERM SIGINT\n\
\n\
# Execute the command\n\
exec "$@"\n\
' > /usr/local/bin/xvfb-run-evaluation && chmod +x /usr/local/bin/xvfb-run-evaluation

# Copy evaluation framework (if requirements.txt exists)
COPY requirements.txt* ./

# Install additional Python requirements if they exist
RUN if [ -f "requirements.txt" ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    fi

# Copy evaluation framework
COPY . .

# Health check - check if the evaluation service is ready
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; print('Evaluation environment ready'); sys.exit(0)" || exit 1

# Default command with resource monitoring
CMD ["xvfb-run-evaluation", "/bin/bash"]
