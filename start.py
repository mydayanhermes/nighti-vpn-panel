import os
import sys

port = os.environ.get('PORT', '8000')
sys.stdout.write(f"STARTUP: PORT from env: {port}\n")
sys.stdout.flush()

# Start gunicorn
os.execvp('gunicorn', [
    'gunicorn', 'app:app',
    '--bind', f'0.0.0.0:{port}',
    '--workers', '2',
    '--threads', '4',
    '--access-logfile', '-'
])
