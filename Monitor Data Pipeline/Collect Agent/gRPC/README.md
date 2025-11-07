python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./generate_protos.sh
python3 server.py