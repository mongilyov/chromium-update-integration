#!/usr/bin/env python3
"""
Извлекает открытый ключ ГОСТ Р 34.10-2012 из контейнера КриптоПро
и выводит C-массив uint64_t слов (X||Y, little-endian), дополненный нулями
до размера буфера (по умолчанию 16 слов / 128 байт).

Основной способ (требуется csptest из КриптоПро CSP):
    python3 extract_public_key.py --key-container="имя_контейнера"

Для 512-битного ключа укажите --provtype 81 (по умолчанию 80, ГОСТ-2012/256).
Размер открытого ключа определяется автоматически; pubkey.bin не нужен.
Тип ключа выбирается автоматически: exchange, а при его отсутствии — signature.
Для явного выбора используйте --key-type exchange или --key-type signature.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile


def find_csptest(explicit_path: str = None) -> str:
    """Ищет csptest в PATH и стандартных каталогах КриптоПро."""
    if explicit_path:
        return explicit_path
    executable = shutil.which("csptest")
    if executable:
        return executable

    if os.name == "nt":
        candidates = [
            Path(root) / "Crypto Pro" / "CSP" / "csptest.exe"
            for name in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)")
            if (root := os.environ.get(name))
        ]
    else:
        base = Path("/opt/cprocsp/bin")
        candidates = [base / "csptest", *sorted(base.glob("*/csptest"))]
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise ValueError(
        "csptest не найден. Установите КриптоПро CSP или укажите --csptest PATH"
    )


def public_key_from_blob(blob: bytes) -> bytes:
    """Убирает заголовок PUBLICKEYBLOB и ASN.1-параметры, сохраняя X||Y LE."""
    # CRYPT_PUBLICKEYBLOB: BLOBHEADER, magic, bitlen, DER SEQUENCE, X||Y.
    if len(blob) < 18:
        raise ValueError("Слишком короткий PUBLICKEYBLOB от csptest")
    kind, version, reserved, _algorithm, magic, bitlen = struct.unpack_from(
        "<BBHIII", blob
    )
    if (kind, version, reserved, magic) != (6, 0x20, 0, 0x3147414D):
        raise ValueError("csptest вернул неподдерживаемый PUBLICKEYBLOB ГОСТ")
    # bitlen задаёт размер обеих координат: 512 или 1024 бита.
    if bitlen not in (512, 1024):
        raise ValueError(f"Неподдерживаемый размер открытого ключа: {bitlen} бит")
    if blob[16] != 0x30:
        raise ValueError("В PUBLICKEYBLOB отсутствуют ASN.1-параметры ключа")
    size = blob[17]
    start = 18
    if size & 0x80:
        count = size & 0x7F
        if not 1 <= count <= 4 or start + count > len(blob):
            raise ValueError("Некорректная длина ASN.1-параметров ключа")
        size = int.from_bytes(blob[start:start + count], "big")
        start += count
    start += size
    if len(blob) - start != bitlen // 8:
        raise ValueError("Размер PUBLICKEYBLOB не совпадает с длиной открытого ключа")
    return blob[start:]


def public_key_from_container(
    container: str,
    csptest: str = None,
    provtype: int = 80,
    key_type: str = "auto",
    pin: str = None,
) -> bytes:
    """Экспортирует только открытый ключ; временный файл удаляется и при ошибке."""
    executable = find_csptest(csptest)
    key_types = ("exchange", "signature") if key_type == "auto" else (key_type,)
    failures = []
    with tempfile.TemporaryDirectory(prefix="extract-public-key-") as directory:
        for selected_type in key_types:
            exported = Path(directory) / f"{selected_type}.blob"
            command = [
                executable, "-keyset", "-silent", "-container", container,
                "-provtype", str(provtype), "-keytype", selected_type,
                "-export", str(exported),
            ]
            if pin is not None:
                command.extend(["-password", pin])
            result = subprocess.run(command, capture_output=True, text=True, errors="replace")
            if result.returncode == 0:
                if not exported.is_file():
                    raise ValueError("csptest завершился без ошибки, но не создал файл открытого ключа")
                return public_key_from_blob(exported.read_bytes())

            details = "\n".join(
                output.strip() for output in (result.stdout, result.stderr) if output.strip()
            )
            # В Unix код завершения усечён до 8 бит; полный код есть в журнале.
            codes = re.findall(r"\[ErrorCode:\s*(0x[0-9a-f]+)\]", details, re.IGNORECASE)
            error_code = int(codes[-1], 16) if codes else result.returncode & 0xFFFFFFFF
            if pin:
                details = details.replace(pin, "***")
            failures.append(
                f"Ключ {selected_type} (код csptest: 0x{error_code:08x}):\n{details}"
            )
            # NTE_NO_KEY / NTE_KEYSET_NOT_DEF: пробуем другой тип ключа.
            # Ошибки доступа, PIN и другие ошибки повторно не обрабатываем.
            if error_code not in (0x8009000D, 0x80090019):
                break
    raise ValueError(
        "Не удалось экспортировать открытый ключ из контейнера.\n" + "\n".join(failures)
    )


def bytes_to_words(data: bytes) -> list[int]:
    """Разбивает байты на 8-байтные little-endian слова."""
    if len(data) % 8 != 0:
        raise ValueError(f"Длина данных ({len(data)}) не кратна 8 байтам")
    words = []
    for i in range(0, len(data), 8):
        chunk = data[i:i + 8]
        # little-endian: младший байт первый
        word = int.from_bytes(chunk, byteorder="little")
        words.append(word)
    return words


def format_c_array(words: list[int], total_words: int, per_line: int = 4) -> str:
    padded = words + [0] * (total_words - len(words))
    lines = []
    for i in range(0, len(padded), per_line):
        chunk = padded[i:i + per_line]
        formatted = ", ".join(f"0x{w:016x}" for w in chunk)
        lines.append(f"\t\t{formatted},")
    # убрать запятую в самом конце
    lines[-1] = lines[-1].rstrip(",")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Устаревший способ (deprecated, оставлен для совместимости):\n"
            "    python3 extract_public_key.py --file pubkey.bin [--offset N] [--length 64]\n"
            "    Файл должен содержать сырые байты X||Y, без заголовка PUBLICKEYBLOB."
        ),
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--key-container", metavar="NAME", help="Имя контейнера КриптоПро (основной способ)")
    parser.add_argument("--provtype", type=int, choices=(80, 81), default=80,
                        help="Тип провайдера: 80 — ГОСТ-2012/256, 81 — ГОСТ-2012/512 (по умолчанию 80)")
    parser.add_argument("--key-type", choices=("auto", "exchange", "signature"), default="auto",
                        help="Ключ в контейнере (по умолчанию auto: exchange, затем signature при отсутствии exchange)")
    parser.add_argument("--csptest", metavar="PATH", help="Путь к csptest, если он не найден автоматически")
    parser.add_argument("--pin", help="Пароль контейнера, если требуется для экспорта")
    parser.add_argument("--total-words", type=int, default=16, help="Общий размер буфера в 8-байтных словах (по умолчанию 16)")
    src.add_argument("--hex", help="Hex-строка с сырыми байтами ключа")
    parser.add_argument("--offset", type=int, default=None, help="Только для --file: смещение в байтах (по умолчанию 0)")
    parser.add_argument("--length", type=int, default=None, help="Для --file/--hex: длина ключа в байтах (по умолчанию 64)")
    src.add_argument("--file", help="Deprecated: файл с сырыми байтами ключа; используйте --key-container")
    args = parser.parse_args()

    if args.total_words <= 0:
        parser.error("--total-words должен быть больше нуля")
    if args.length is not None and args.length <= 0:
        parser.error("--length должен быть больше нуля")
    if args.offset is not None and (args.offset < 0 or args.file is None):
        parser.error("--offset должен быть неотрицательным и используется только с --file")
    if args.key_container is not None:
        if not args.key_container.strip():
            parser.error("--key-container не может быть пустым")
        if args.length is not None:
            parser.error("С --key-container длина ключа определяется автоматически; уберите --length")

    try:
        if args.key_container is not None:
            data = public_key_from_container(
                args.key_container, args.csptest, args.provtype, args.key_type, args.pin
            )
        else:
            length = args.length if args.length is not None else 64
            if args.hex is not None:
                try:
                    data = bytes.fromhex(args.hex.strip().replace(" ", ""))
                except ValueError as e:
                    raise ValueError(f"некорректная hex-строка: {e}") from e
            else:
                with open(args.file, "rb") as f:
                    f.seek(args.offset or 0)
                    data = f.read(length)
            if len(data) != length:
                print(
                    f"Предупреждение: прочитано {len(data)} байт вместо ожидаемых {length}",
                    file=sys.stderr,
                )
        words = bytes_to_words(data)
    except (OSError, ValueError) as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1

    if len(words) > args.total_words:
        print(
            f"Ошибка: данных больше ({len(words)} слов), чем размер буфера ({args.total_words} слов)",
            file=sys.stderr,
        )
        return 1

    print(format_c_array(words, args.total_words))
    return 0


if __name__ == "__main__":
    # Русская справка должна работать и в Windows с перенаправленным выводом.
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())

