#!/usr/bin/env python3
"""Основной скрипт парсера освобождающихся доменов REG.RU."""

import argparse
import configparser
import csv
from datetime import datetime
import os
import sys
from typing import Dict, List

from regru_client import RegRuClient


def parse_date(date_str: str) -> str:
    """Проверяет формат ДД.ММ.ГГГГ и переводит в ГГГГ-ММ-ДД для reg.ru."""
    date_str = date_str.strip()
    try:
        dt = datetime.strptime(date_str, "%d.%m.%Y")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass

    # Если пользователь передал в формате YYYY-MM-DD
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        raise ValueError(
            f"Некорректный формат даты: '{date_str}'. "
            f"Ожидается формат ДД.ММ.ГГГГ (например: 15.10.2026)"
        )


def load_config(config_path: str = "config.ini") -> Dict:
    """Загружает параметры из config.ini с дефолтными значениями."""
    config = configparser.ConfigParser()
    settings = {
        "target_date": "",
        "output_format": "txt",
        "output_file": "",
        "request_delay": 3.0,
        "max_pages": 0,
    }

    if os.path.exists(config_path):
        config.read(config_path, encoding="utf-8")
        if "settings" in config:
            sec = config["settings"]
            settings["target_date"] = sec.get("target_date", "").strip()
            settings["output_format"] = sec.get("output_format", "txt").strip().lower()
            settings["output_file"] = sec.get("output_file", "").strip()
            try:
                settings["request_delay"] = float(sec.get("request_delay", "3.0"))
            except ValueError:
                pass
            try:
                settings["max_pages"] = int(sec.get("max_pages", "0"))
            except ValueError:
                pass

    return settings


def save_domains_txt(domains: List[Dict], filepath: str) -> None:
    """Сохраняет имена доменов в текстовый файл по одному на строку."""
    with open(filepath, "w", encoding="utf-8") as f:
        for item in domains:
            f.write(f"{item['name']}\n")


def save_domains_csv(domains: List[Dict], filepath: str) -> None:
    """Сохраняет подробную информацию о доменах в CSV-файл."""
    fieldnames = [
        "name",
        "release_date",
        "min_price",
        "max_price",
        "domain_age",
        "current_bid",
        "first_registration",
    ]
    with open(filepath, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for item in domains:
            writer.writerow({k: item.get(k, "") for k in fieldnames})


def main():
    config_defaults = load_config()

    parser = argparse.ArgumentParser(
        description="Парсер освобождающихся доменов с reg.ru/domain/new/rereg"
    )
    parser.add_argument(
        "--date",
        "-d",
        default=config_defaults["target_date"],
        help="Дата освобождения в формате ДД.ММ.ГГГГ (например, 15.10.2026)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=config_defaults["output_file"],
        help="Имя выходного файла (по умолчанию: domains_ДД.ММ.ГГГГ.[txt|csv])",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["txt", "csv"],
        default=config_defaults["output_format"],
        help="Формат вывода: txt (только домены) или csv (с деталями)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=config_defaults["request_delay"],
        help="Задержка между запросами в секундах (по умолчанию 3.0)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=config_defaults["max_pages"],
        help="Максимальное число страниц (0 — без ограничений)",
    )

    args = parser.parse_args()

    target_date = args.date
    if not target_date:
        try:
            target_date = input("Введите дату освобождения (ДД.ММ.ГГГГ, например 15.10.2026): ").strip()
        except (EOFError, KeyboardInterrupt):
            pass

    if not target_date:
        print("Ошибка: Дата освобождения не указана!")
        print("Укажите её в config.ini (target_date = ДД.ММ.ГГГГ) или через аргумент --date.")
        if not sys.argv[1:]:
            try:
                input("\nНажмите Enter для выхода...")
            except (EOFError, KeyboardInterrupt):
                pass
        sys.exit(1)

    try:
        iso_date = parse_date(target_date)
    except ValueError as e:
        print(f"Ошибка: {e}")
        if not sys.argv[1:]:
            try:
                input("\nНажмите Enter для выхода...")
            except (EOFError, KeyboardInterrupt):
                pass
        sys.exit(1)


    display_date = datetime.strptime(iso_date, "%Y-%m-%d").strftime("%d.%m.%Y")
    fmt = args.format.lower()
    output_path = args.output
    if not output_path:
        output_path = f"domains_{display_date}.{fmt}"

    print(f"=== Запуск парсера освобождающихся доменов REG.RU ===")
    print(f"Дата освобождения: {display_date} ({iso_date})")
    print(f"Формат сохранения: {fmt.upper()}")
    print(f"Выходной файл:     {output_path}")
    print(f"Интервал запросов: {args.delay} сек.")
    print("-----------------------------------------------------")

    client = RegRuClient(request_delay=args.delay)

    print("Подключение к reg.ru и прохождение проверки защиты...")
    try:
        first_page_domains, max_pg = client.init_filter(iso_date)
    except Exception as e:
        print(f"Ошибка при подключении к reg.ru: {e}")
        sys.exit(1)

    all_domains = list(first_page_domains)
    total_pages = max_pg + 1 if first_page_domains else 0

    if total_pages == 0:
        print(f"Доменов с датой освобождения {display_date} не найдено.")
        sys.exit(0)

    print(f"Найдено страниц: {total_pages} (первая страница: {len(first_page_domains)} доменов)")

    pages_to_fetch = max_pg
    if args.max_pages > 0 and args.max_pages < total_pages:
        pages_to_fetch = args.max_pages - 1
        print(f"Ограничение количества страниц: {args.max_pages}")

    for pg in range(1, pages_to_fetch + 1):
        print(f"Загрузка страницы {pg + 1}/{total_pages} (всего собрано: {len(all_domains)})...")
        try:
            domains = client.fetch_page(pg)
            if not domains:
                print(f"Страница {pg + 1} пуста, завершение пагинации.")
                break
            all_domains.extend(domains)
        except Exception as e:
            print(f"Предупреждение: ошибка при загрузке страницы {pg + 1}: {e}")
            break

    print("-----------------------------------------------------")
    print(f"Сбор завершен! Всего найдено доменов: {len(all_domains)}")

    # Удаляем возможные дубликаты с сохранением порядка
    seen = set()
    unique_domains = []
    for d in all_domains:
        if d["name"] not in seen:
            seen.add(d["name"])
            unique_domains.append(d)

    if len(unique_domains) < len(all_domains):
        print(f"Уникальных доменов: {len(unique_domains)}")

    # Сохраняем в файл
    if fmt == "csv":
        save_domains_csv(unique_domains, output_path)
    else:
        save_domains_txt(unique_domains, output_path)

    print(f"Результаты успешно сохранены в файл: {output_path}")
    if not sys.argv[1:]:
        try:
            input("\nНажмите Enter, чтобы закрыть окно...")
        except (EOFError, KeyboardInterrupt):
            pass


if __name__ == "__main__":
    main()
