import os
import base64
import getpass
from cryptography.fernet import Fernet
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
    print(f"\n{C.RED}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════════════════╗")
    print("  ║          CRYPTVAULT  //  FILE ENCRYPTION ENGINE           ║")
    print(f"  ║    Algorithm : AES-128-CBC   KDF : PBKDF2-SHA256  v{VERSION}   ║")
    print("  ╠══════════════════════════════════════════════════════════╣")
    print(f"  ║    Developed by {C.YELLOW}{AUTHOR}{C.RED}                                      ║")
    print("  ╚══════════════════════════════════════════════════════════╝")
    print(C.RESET)

def info(msg):       print(f"  {C.CYAN}[*]{C.RESET}  {msg}")
def success(msg):    print(f"  {C.GREEN}[+]{C.RESET}  {msg}")
def warning(msg):    print(f"  {C.YELLOW}[!]{C.RESET}  {msg}")
def error(msg):      print(f"  {C.RED}[-]{C.RESET}  {msg}")
def field(k, v):     print(f"  {C.GRAY}     {k:<22}{C.RESET}{C.WHITE}{v}{C.RESET}")
def sep():           print(f"  {C.GRAY}{LINE}{C.RESET}")

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


def encrypt_file(file_path: str) -> bool:
    if not os.path.isfile(file_path):
        error(f"Target not found: {file_path}")
        return False

    file_name  = os.path.basename(file_path)
    file_size  = os.path.getsize(file_path)
    parent_dir = os.path.dirname(os.path.abspath(file_path))

    # Output paths
    # Rutas de salida
    locked_path = file_path + '.locked'
    key_path    = file_path + '.key'

    sep()
    info("Target acquired")
    field("File:",     file_name)
    field("Size:",     f"{file_size:,} bytes")
    field("Path:",     parent_dir)
    field("Output:",   file_name + '.locked')
    field("Key file:", file_name + '.key')
    sep()

    # Password prompt
    # Solicitud de contraseña
    print()
    try:
        password = getpass.getpass(f"  {C.YELLOW}[?]{C.RESET}  Set encryption password   : ")
        confirm  = getpass.getpass(f"  {C.YELLOW}[?]{C.RESET}  Confirm password          : ")
    except (KeyboardInterrupt, EOFError):
        print()
        warning("Operation aborted by user.")
        return False

    if password != confirm:
        error("Passwords do not match. Aborting.")
        return False

    if len(password) < 4:
        error("Password too short. Minimum length: 4 characters.")
        return False

    print()
    info("Deriving encryption key  [PBKDF2-SHA256 / 480,000 rounds] ...")

    salt        = os.urandom(SALT_SIZE)
    derived_key = derive_key(password, salt)

    # Generate session key and encrypt the file content
    # Generar clave de sesión y cifrar el contenido del archivo
    session_key = Fernet.generate_key()
    cipher      = Fernet(session_key)

    info("Encrypting target file ...")

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(plaintext)

    # Write encrypted content to archivo.ext.locked
    # Escribir el contenido cifrado en archivo.ext.locked
    with open(locked_path, 'wb') as f:
        f.write(ciphertext)

    # Protect the session key with the password-derived key
    # .key layout: [16-byte salt][Fernet-encrypted session key]
    # Proteger la clave de sesión con la clave derivada de la contraseña
    # estructura .key: [sal de 16 bytes][clave de sesión cifrada con Fernet]
    key_cipher = Fernet(derived_key)
    locked_key = key_cipher.encrypt(session_key)

    with open(key_path, 'wb') as f:
        f.write(salt + locked_key)

    # Remove the original unencrypted file
    # Eliminar el archivo original sin cifrar
    os.remove(file_path)

    sep()
    success("Encryption complete.")
    sep()
    field("Encrypted file:",  os.path.basename(locked_path))
    field("Key file:",        os.path.basename(key_path))
    field("Original:",        f"{file_name}  [removed]")
    field("KDF iterations:",  f"{PBKDF2_ITERATIONS:,}")
    field("Salt (hex):",      salt.hex())
    sep()
    print()
    warning("The .key file is cryptographically bound to your password.")
    warning("Without the correct password, decryption is computationally infeasible.")
    warning("Store the .key file in a secure location.")
    
    # Spanish warnings
    # Advertencias en español
    warning("El archivo .key está vinculado criptográficamente a tu contraseña.")
    warning("Sin la contraseña correcta, el descifrado es computacionalmente inviable.")
    warning("Guarda el archivo .key en un lugar seguro.")
    print()
    return True


def main():
    banner()

    print(f"  {C.GRAY}Drag the target file onto this window and press Enter,")
    print(f"  or type the full file path manually.{C.RESET}\n")
    
    # Spanish instruction
    # Instrucción en español
    print(f"  {C.GRAY}Arrastra el archivo objetivo a esta ventana y presiona Enter,")
    print(f"  o escribe la ruta completa del archivo manualmente.{C.RESET}\n")

    try:
        raw = input(f"  {C.CYAN}[>]{C.RESET}  Target file path : ").strip().strip('"').strip("'")
    except (KeyboardInterrupt, EOFError):
        print()
        warning("Operation aborted.")
        input("\n  Press Enter to exit...")
        return

    if not raw:
        error("No path provided. Exiting.")
        input("\n  Press Enter to exit...")
        return

    encrypt_file(raw)
    input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
