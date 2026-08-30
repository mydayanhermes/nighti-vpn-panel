import os
import sys

port = os.environ.get('PORT', '8000')
print(f"PORT from env: {port}")

# Start gunicorn
os.execvp('gunicorn', [
    'gunicorn', 'app:app',
    '--bind', f'0.0.0.0:{port}',
    '--workers', '2',
    '--threads', '4'
])
