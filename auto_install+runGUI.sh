python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt

if [ -f .env.example ]; then
  cp .env.example .env
  open -W .env
fi

python3 ./bambu_gui.py