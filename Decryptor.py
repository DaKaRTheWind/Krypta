import os
import base64
import getpass
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Enable ANSI escape codes on Windows
# Habilitar códigos de escape ANSI en Windows
os.system('')

# ── ANSI Color Palette ────────────────────────────────────────────────────────
# ── Paleta de Colores ANSI ────────────────────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GRAY   = '\033[90m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

# ── Constants ─────────────────────────────────────────────────────────────────
# ── Constantes ────────────────────────────────────────────────────────────────
SALT_SIZE         = 16
PBKDF2_ITERATIONS = 480_000
VERSION           = "1.0"
AUTHOR            = "DaKaR"
LINE              = '─' * 60

# ── UI Helpers ────────────────────────────────────────────────────────────────
# ── Ayudantes de Interfaz de Usuario ──────────────────────────────────────────
def banner():
    print(f"\n{C.GREEN}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║          CRYPTVAULT  //  FILE DECRYPTION ENGINE           ║")
    print(f"  ║    Algorithm : AES-128-CBC   KDF : PBKDF2-SHA256  v{VERSION}   ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print(f"  ║    Developed by {C.YELLOW}{AUTHOR}{C.GREEN}                                      ║")        
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(C.RESET)

def info(msg):       print(f"  {C.CYAN}[*]{C.RESET}  {msg}")
def success(msg):    print(f"  {C.GREEN}[+]{C.RESET}  {msg}")
def warning(msg):    print(f"  {C.YELLOW}[!]{C.RESET}  {msg}")
def error(msg):      print(f"  {C.RED}[-]{C.RESET}  {msg}")
def field(k, v):     print(f"  {C.GRAY}     {k:<22}{C.RESET}{C.WHITE}{v}{C.RESET}")
def sep():           print(f"  {C.GRAY}{LINE}{C.RESET}")

def prompt(label: str) -> str:
    raw = input(label).strip()
    return raw.strip('"').strip("'")

# ── Core ──────────────────────────────────────────────────────────────────────
# ── Núcleo ────────────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key via PBKDF2-SHA256.
    Deriva una clave de 32 bytes compatible con Fernet mediante PBKDF2-SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))


def decrypt_file(file_path: str, key_file_path: str) -> bool:
    if not os.path.isfile(file_path):
        error(f"Target not found: {file_path}")
        return False

    if not os.path.isfile(key_file_path):
        error(f"Key file not found: {key_file_path}")
        return False

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    # Read key file: [16-byte salt][encrypted session key]
    # Leer archivo de clave: [sal de 16 bytes][clave de sesión cifrada]
    with open(key_file_path, 'rb') as f:
        key_data = f.read()

    if len(key_data) <= SALT_SIZE:
        error("Key file is corrupted or invalid.")
        return False

    salt       = key_data[:SALT_SIZE]
    locked_key = key_data[SALT_SIZE:]

    # Determine the restored output path (strip .locked suffix)
    # Determinar la ruta de salida restaurada (eliminar el sufijo .locked)
    if file_path.endswith('.locked'):
        restored_path = file_path[:-7]
    else:
        restored_path = file_path + '.decrypted'

    sep()
    info("Target acquired")
    field("File:",         file_name)
    field("Size:",         f"{file_size:,} bytes")
    field("Key file:",     os.path.basename(key_file_path))
    field("Restore as:",   os.path.basename(restored_path))
    field("Salt (hex):",   salt.hex())
    sep()

    # Password prompt
    # Solicitud de contraseña
    print()
    try:
        password = getpass.getpass(f"  {C.YELLOW}[?]{C.RESET}  Enter decryption password : ")
    except (KeyboardInterrupt, EOFError):
        print()
        warning("Operation aborted by user.")
        return False

    print()
    info("Deriving key from password  [PBKDF2-SHA256 / 480,000 rounds] ...")

    derived_key = derive_key(password, salt)

    # Attempt to unlock the session key
    # Intentar desbloquear la clave de sesión
    try:
        key_cipher  = Fernet(derived_key)
        session_key = key_cipher.decrypt(locked_key)
    except InvalidToken:
        error("Incorrect password. Decryption aborted.")
        return False

    info("Session key recovered. Decrypting target file ...")

    # Decrypt the file
    # Descifrar el archivo
    try:
        cipher = Fernet(session_key)

        with open(file_path, 'rb') as f:
            ciphertext = f.read()

        plaintext = cipher.decrypt(ciphertext)
    except InvalidToken:
        error("File decryption failed. Key file does not match this target.")
        return False

    # Write the restored file (without .locked suffix)
    # Escribir el archivo restaurado (sin el sufijo .locked)
    with open(restored_path, 'wb') as f:
        f.write(plaintext)

    # Remove the .locked file and the .key file
    # Eliminar el archivo .locked y el archivo .key
    removed = []
    for path in (file_path, key_file_path):
        try:
            os.remove(path)
            removed.append(os.path.basename(path))
        except Exception:
            pass

    sep()
    success("Decryption complete. File restored to original state.")
    sep()
    field("Restored file:",   os.path.basename(restored_path))
    field("Restored size:",   f"{len(plaintext):,} bytes")
    field("Removed:",         "  ".join(removed) if removed else "none")
    sep()
    print()
    return True


def main():
    banner()

    print(f"  {C.GRAY}Drag the encrypted (.locked) file onto this window and press Enter,")
    print(f"  or type the full file path manually.{C.RESET}\n")
    
    # Spanish instruction
    # Instrucción en español
    print(f"  {C.GRAY}Arrastra el archivo cifrado (.locked) a esta ventana y presiona Enter,")
    print(f"  o escribe la ruta completa del archivo manualmente.{C.RESET}\n")

    # Get encrypted file path
    # Obtener la ruta del archivo cifrado
    try:
        file_path = prompt(f"  {C.CYAN}[>]{C.RESET}  Encrypted file path (.locked) : ")
    except (KeyboardInterrupt, EOFError):
        print()
        warning("Operation aborted.")
        input("\n  Press Enter to exit...")
        return

    if not file_path:
        error("No path provided. Exiting.")
        input("\n  Press Enter to exit...")
        return

    print()

    # Auto-detect the .key file (same base name, .key extension)
    # Auto-detectar el archivo .key (mismo nombre base, extensión .key)
    auto_key = file_path[:-7] + '.key' if file_path.endswith('.locked') else file_path + '.key'

    if os.path.isfile(auto_key):
        info(f"Key file detected: {os.path.basename(auto_key)}")
        try:
            choice = input(f"  {C.CYAN}[>]{C.RESET}  Use this key file? [Y/n]        : ").strip().lower()       
        except (KeyboardInterrupt, EOFError):
            print()
            warning("Operation aborted.")
            input("\n  Press Enter to exit...")
            return

        key_file_path = auto_key if choice in ('', 'y', 'yes') else None

        if key_file_path is None:
            try:
                key_file_path = prompt(f"  {C.CYAN}[>]{C.RESET}  Key file path (.key)           : ")
            except (KeyboardInterrupt, EOFError):
                print()
                warning("Operation aborted.")
                input("\n  Press Enter to exit...")
                return
    else:
        try:
            key_file_path = prompt(f"  {C.CYAN}[>]{C.RESET}  Key file path (.key)           : ")
        except (KeyboardInterrupt, EOFError):
            print()
            warning("Operation aborted.")
            input("\n  Press Enter to exit...")
            return

    if not key_file_path:
        error("No key file path provided. Exiting.")
        input("\n  Press Enter to exit...")
        return

    decrypt_file(file_path, key_file_path)
    input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
