# HeadrEval

HeadrEval is a command-line tool for evaluating security headers of a given URL.

## Features

- Performs evaluation of security headers for a specified URL.
- Lists the headers without performing a security evaluation.
- Provides information and recommendations based on security header evaluations.

## Getting Started

1. Clone the repository:

  ```bash
  git clone https://github.com/Schwitzd/HeadrEval.git
  ```

2. Create a Python virtual environment and activate it (optional):

  ```bash
  cd HeadrEval
  python -m venv .env
  source .env/bin/activate
  ```

3. Install the module:

```bash
pip install -e .
```

## Usage

```help
HeadrEval -h

 _   _                _      _____           _ 
| | | |              | |    |  ___|         | |
| |_| | ___  __ _  __| |_ __| |____   ____ _| |
|  _  |/ _ \/ _` |/ _` | '__|  __\ \ / / _` | |
| | | |  __/ (_| | (_| | |  | |___\ V / (_| | |
\_| |_/\___|\__,_|\__,_|_|  \____/ \_/ \__,_|_|
                                         v0.6.0                                               


usage: HeadrEval [-h] -U URL [-L]

options:
  -h, --help         show this help message and exit
  -U URL, --url URL  Url to scan
  -L, --list         list headers without do a security evaluation
```

## License

This project is licensed under the [MIT License](https://github.com/AggressiveUser/AllForOne/blob/main/LICENSE)
