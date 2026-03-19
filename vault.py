import os
import json
import base64
import getpass
import time
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

# S8: Fixed path — independent of working directory
VAULT_DIR = Path.home() / ".vibevault"
VAULT_FILE = VAULT_DIR / "vault.enc"

# S5: Salt size 16 → 32 bytes
SALT_SIZE = 32
# S4: PBKDF2 iterations 100,000 → 600,000 (NIST 2023 recommendation for SHA-256)
PBKDF2_ITERATIONS = 600_000
# S3: Brute-force protection
MAX_ATTEMPTS = 5

# Paths for old-format migration
_OLD_VAULT = Path("vault.json.enc")
_OLD_SALT  = Path("salt.bin")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_vault(password: str) -> tuple[dict, bytes, bytes]:
    """
    Returns (vault_dict, salt, key).
    Raises FileNotFoundError if no vault exists yet.
    Raises ValueError on wrong password.
    Raises OSError on file corruption.
    """
    if not VAULT_FILE.exists():
        raise FileNotFoundError("vault not found")

    with open(VAULT_FILE, "rb") as f:
        file_data = f.read()

    if len(file_data) < SALT_SIZE:
        raise OSError("金庫檔案損壞：資料不足")

    # S6: Salt is embedded in the first SALT_SIZE bytes of the vault file
    salt = file_data[:SALT_SIZE]
    encrypted_data = file_data[SALT_SIZE:]
    key = derive_key(password, salt)

    try:
        decrypted_data = Fernet(key).decrypt(encrypted_data)
    except InvalidToken:
        raise ValueError("Master Password 錯誤")

    try:
        return json.loads(decrypted_data.decode()), salt, key
    except json.JSONDecodeError as e:
        raise OSError(f"金庫資料損壞：{e}")


def save_vault(key: bytes, salt: bytes, data: dict) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    encrypted_data = Fernet(key).encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as f:
        # S6: Write salt + ciphertext as a single file
        f.write(salt + encrypted_data)
    # S7: Restrict permissions to owner read/write only
    os.chmod(VAULT_FILE, 0o600)


def _migrate_old_format(password: str) -> bool:
    """Migrate vault.json.enc + salt.bin → new single-file format. Returns True if migrated."""
    if not _OLD_VAULT.exists() or not _OLD_SALT.exists() or VAULT_FILE.exists():
        return False

    with open(_OLD_SALT, "rb") as f:
        old_salt = f.read()

    # Old format used 100,000 iterations
    old_kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=old_salt, iterations=100_000)
    old_key = base64.urlsafe_b64encode(old_kdf.derive(password.encode()))

    try:
        with open(_OLD_VAULT, "rb") as f:
            enc = f.read()
        data = json.loads(Fernet(old_key).decrypt(enc).decode())
    except (InvalidToken, json.JSONDecodeError):
        return False

    new_salt = os.urandom(SALT_SIZE)
    new_key = derive_key(password, new_salt)
    save_vault(new_key, new_salt, data)
    print(f"✅ 舊格式金庫已遷移至 {VAULT_FILE}（原檔案保留未刪除）。")
    return True


def main() -> None:
    print("--- 🛡️ VibeVault v3.0 | 安全加密金庫 ---")

    vault: dict = {}
    salt: bytes = b""
    key: bytes = b""

    # S3: Brute-force protection with exponential back-off
    for attempt in range(1, MAX_ATTEMPTS + 1):
        master_pw = getpass.getpass("請輸入 Master Password (K輸入時不會顯示): ")

        # Check for old-format migration on first attempt
        if attempt == 1:
            _migrate_old_format(master_pw)

        try:
            vault, salt, key = load_vault(master_pw)
            break
        except FileNotFoundError:
            salt = os.urandom(SALT_SIZE)
            key = derive_key(master_pw, salt)
            vault = {}
            print("✨ 未找到金庫，將建立新金庫。")
            break
        except ValueError:
            remaining = MAX_ATTEMPTS - attempt
            if remaining == 0:
                print("❌ 超過最大嘗試次數，程式結束。")
                return
            delay = min(2 ** attempt, 30)
            print(f"❌ Master Password 錯誤！剩餘嘗試次數：{remaining}，請等待 {delay} 秒...")
            time.sleep(delay)
        except OSError as e:
            print(f"❌ {e}")
            return

    while True:
        print("\n" + "=" * 30)
        print("[1] 搜尋  [2] 新增  [3] 列表  [4] 刪除  [5] 批次匯入  [6] 退出")
        action = input("請選擇操作: ").strip()

        if action == "1":
            keyword = input("欲搜尋的關鍵字: ").lower()
            results = {k: v for k, v in vault.items() if keyword in k.lower()}
            if not results:
                print("🔍 找不到相關結果。")
            else:
                for site, info in results.items():
                    print(f"📌 {site} -> 帳號: {info['user']} | 密碼: {info['pass']}")

        elif action == "2":
            site = input("網站/服務名稱: ")
            if site in vault:
                old = vault[site]
                print(f"⚠️  '{site}' 已存在 -> 帳號: {old['user']} | 密碼: {old['pass']}")
                if input("確定要覆蓋？(y/n): ").lower() != "y":
                    print("已取消。")
                    continue
            account = input("帳號: ")
            # S1: Use getpass so the password is not echoed to terminal
            pwd = getpass.getpass("密碼 (輸入時不會顯示): ")
            vault[site] = {"user": account, "pass": pwd}
            save_vault(key, salt, vault)
            print(f"✅ '{site}' 已成功加密存儲！")

        elif action == "3":
            if not vault:
                print("📭 金庫目前是空的。")
            else:
                print("\n--- 目前儲存的所有服務 ---")
                for i, site in enumerate(vault.keys(), 1):
                    print(f"[{i}] {site}")

        elif action == "4":
            if not vault:
                print("📭 沒有可刪除的項目。")
                continue

            keys = list(vault.keys())
            for i, site in enumerate(keys, 1):
                print(f"[{i}] {site}")

            try:
                idx = int(input("請輸入欲刪除的編號: ")) - 1
                if 0 <= idx < len(keys):
                    removed_site = keys[idx]
                    if input(f"確定要刪除 '{removed_site}' 嗎？(y/n): ").lower() == "y":
                        del vault[removed_site]
                        save_vault(key, salt, vault)
                        print(f"🗑️ 已刪除項目: {removed_site}")
                else:
                    print("⚠️ 無效的編號。")
            except ValueError:
                print("⚠️ 請輸入數字。")

        elif action == "5":
            path_str = input("passwd.txt 路徑 (直接 Enter 使用當前目錄): ").strip()
            import_path = Path(path_str) if path_str else Path("passwd.txt")
            if not import_path.exists():
                print(f"❌ 找不到檔案：{import_path}")
            else:
                added = skipped = errors = 0
                with open(import_path, "r", encoding="utf-8") as f:
                    for lineno, line in enumerate(f, 1):
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(",", 2)
                        if len(parts) != 3:
                            print(f"⚠️  第 {lineno} 行格式錯誤（需為 網站,帳號,密碼），已略過。")
                            errors += 1
                            continue
                        site_i, user_i, pass_i = (p.strip() for p in parts)
                        if site_i in vault:
                            old = vault[site_i]
                            print(f"⚠️  '{site_i}' 已存在 -> 帳號: {old['user']} | 密碼: {old['pass']}")
                            if input(f"   覆蓋？(y/n): ").lower() != "y":
                                skipped += 1
                                continue
                        vault[site_i] = {"user": user_i, "pass": pass_i}
                        added += 1
                save_vault(key, salt, vault)
                print(f"✅ 批次匯入完成：新增/覆蓋 {added} 筆，略過 {skipped} 筆，格式錯誤 {errors} 筆。")

        elif action == "6":
            print("🔒 金庫已安全關閉。掰掰！")
            break


if __name__ == "__main__":
    main()
