# Cryptographic Hash Functions for y-- (Ymm)

Cryptographic hashing library providing MD5, SHA-1, SHA-256, SHA-3, Keccak, and Double-SHA-256 for y--.

## Installation

This library is an official external module for the **y--** (**Ymm**) programming language. You can install it effortlessly via **`yenv`**:

```bash
yenv install crypto
```

This will automatically clone the repository, build the shared library (`liby-crypto.so` / `y-crypto.dll`), and register it in `~/.yenv/lib/`.

## Usage

```ymm
import Crypto
from Crypto import *

define function main(): {
    digest = Crypto.SHA256("hello world")
    print("SHA-256: " + digest)
}
```

## Documentation

Full documentation, including manual pages and reference texts, are available in the [`docs/`](docs/) directory:
- `crypto.man`: UNIX troff man page
- `crypto.txt`: Plaintext documentation reference

You can view the documentation using:
```bash
man -l docs/crypto.man
```

## License

This project is licensed under the same license as the **y--** programming language. See the [LICENSE](LICENSE) file for details.
