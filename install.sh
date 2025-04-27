#!/bin/bash

# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install flask pyjwt werkzeug

# Create necessary directories
mkdir -p uploads

echo "Installation complete! Run 'python app.py' to start the server."
