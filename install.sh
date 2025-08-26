#!/bin/bash

echo "🚀 Installing PrivAware..."
echo "========================"

# Check if we're in the right directory
if [ ! -d "privaware_pkg" ] || [ ! -f "privaware_pkg/privaware.py" ]; then
    echo "❌ Error: PrivAware files not found. Please run this script from the project root directory."
    exit 1
fi

# Check if virtual environment exists, if not create it
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies from privaware_pkg/requirements.txt
if [ -f "privaware_pkg/requirements.txt" ]; then
    echo "🔧 Installing Python dependencies..."
    pip install -r privaware_pkg/requirements.txt
else
    echo "⚠️  No requirements.txt found, installing basic dependencies..."
    pip install psutil watchdog rich python-dotenv
fi

# Install package in development mode
echo "🔧 Installing PrivAware package..."
pip install -e .

# Create system-wide command
echo "🔧 Creating system-wide command..."
sudo tee /usr/local/bin/privaware > /dev/null << 'EOT'
#!/bin/bash
# PrivAware system launcher
cd /home/$(logname)/Project/privaware 2>/dev/null || cd $(pwd)
source venv/bin/activate 2>/dev/null || true
python3 -m privaware_pkg.privaware "$@"
EOT

sudo chmod +x /usr/local/bin/privaware

echo ""
echo "✅ PrivAware installation complete!"
echo ""
echo "🎉 You can now use:"
echo "   privaware --help              # System-wide command"
echo "   privaware --audit            # Run security audit"
echo "   privaware --realtime-watch   # Real-time file monitoring"
