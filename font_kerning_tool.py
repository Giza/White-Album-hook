#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import csv
import os
import argparse
import sys

def extract_kerning(input_file, output_file):
    """
    Извлекает данные кернинга из бинарного файла и сохраняет их в CSV.
    Каждая запись - 4 байта (2 байта слева и 2 байта справа) для каждого символа,
    начиная с символа 0x20 (пробел).
    """
    print(f"Начинаю извлечение данных из {input_file}...")
    
    with open(input_file, 'rb') as bin_file:
        data = bin_file.read()
    
    # Проверяем, что размер файла кратен 4 (размер записи кернинга)
    if len(data) % 4 != 0:
        print(f"Предупреждение: Размер файла {len(data)} байт не кратен 4.")
    
    kerning_data = []
    char_code = 0x20  # Начинаем с символа пробела (0x20)
    
    for i in range(0, len(data), 4):
        if i + 4 <= len(data):
            left_kerning = struct.unpack('<h', data[i:i+2])[0]  # 2 байта слева
            right_kerning = struct.unpack('<h', data[i+2:i+4])[0]  # 2 байта справа
            
            # Добавляем в список: код символа, символ (если печатаемый), левый и правый кернинг
            char = chr(char_code) if 0x20 <= char_code <= 0x7E else f"U+{char_code:04X}"
            kerning_data.append([char_code, char, left_kerning, right_kerning])
            
            char_code += 1
    
    # Записываем данные в CSV файл
    with open(output_file, 'w', newline='', encoding='utf-8') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(['CharCode', 'Character', 'LeftKerning', 'RightKerning'])
        writer.writerows(kerning_data)
    
    print(f"Данные кернинга извлечены и сохранены в {output_file}")
    print(f"Всего обработано символов: {len(kerning_data)}")

def pack_kerning(input_file, output_file):
    """
    Читает данные кернинга из CSV файла и упаковывает их обратно в бинарный файл.
    """
    print(f"Начинаю упаковку данных из {input_file}...")
    sys.stdout.flush()  # Принудительно выводим буфер
    
    kerning_data = []
    
    try:
        with open(input_file, 'r', newline='', encoding='utf-8') as csv_file:
            reader = csv.reader(csv_file)
            header = next(reader)  # Пропускаем заголовок
            
            print(f"Прочитан заголовок CSV: {header}")
            sys.stdout.flush()
            
            if len(header) < 4:
                print(f"Ошибка: CSV файл не содержит необходимых колонок. Найдено: {header}")
                return
            
            expected_code = 0x20  # Ожидаемый начальный код символа
            
            for row in reader:
                if len(row) >= 4:
                    try:
                        char_code = int(row[0])
                        left_kerning = int(row[2])
                        right_kerning = int(row[3])
                        kerning_data.append((char_code, left_kerning, right_kerning))
                    except ValueError as e:
                        print(f"Ошибка при обработке строки {row}: {e}")
                        sys.stdout.flush()
    except Exception as e:
        print(f"Ошибка при чтении CSV файла: {e}")
        sys.stdout.flush()
        return
    
    print(f"Прочитано {len(kerning_data)} записей из CSV файла")
    sys.stdout.flush()
    
    if not kerning_data:
        print("Ошибка: Нет данных для упаковки. CSV файл пуст или некорректен.")
        return
    
    # Сортируем по коду символа для уверенности
    kerning_data.sort(key=lambda x: x[0])
    
    # Проверяем, что первый символ имеет код 0x20
    if kerning_data[0][0] != 0x20:
        print(f"Предупреждение: Первый символ в CSV имеет код {kerning_data[0][0]}, ожидается 0x20.")
        sys.stdout.flush()
    
    # Создаем бинарные данные
    binary_data = bytearray()
    for _, left, right in kerning_data:
        binary_data.extend(struct.pack('<h', left))  # 2 байта для левого кернинга
        binary_data.extend(struct.pack('<h', right))  # 2 байта для правого кернинга
    
    print(f"Подготовлено {len(binary_data)} байт данных для записи")
    sys.stdout.flush()
    
    # Записываем в бинарный файл
    try:
        with open(output_file, 'wb') as bin_file:
            bin_file.write(binary_data)
        
        print(f"Данные кернинга упакованы и сохранены в {output_file}")
        print(f"Всего обработано символов: {len(kerning_data)}")
        sys.stdout.flush()
    except Exception as e:
        print(f"Ошибка при записи бинарного файла: {e}")
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description='Инструмент для работы с данными кернинга шрифта')
    parser.add_argument('action', choices=['extract', 'pack'], help='Действие: extract (извлечь из bin в csv) или pack (упаковать из csv в bin)')
    parser.add_argument('--input', '-i', required=True, help='Путь к входному файлу (bin или csv)')
    parser.add_argument('--output', '-o', help='Путь к выходному файлу (csv или bin)')
    
    args = parser.parse_args()
    print(f"Запуск программы с параметрами: {args}")
    sys.stdout.flush()
    
    # Определяем имя выходного файла, если не указано
    if not args.output:
        if args.action == 'extract':
            args.output = os.path.splitext(args.input)[0] + '.csv'
        else:
            args.output = os.path.splitext(args.input)[0] + '.bin'
    
    if args.action == 'extract':
        extract_kerning(args.input, args.output)
    else:
        pack_kerning(args.input, args.output)
    
    print("Программа завершена успешно")
    sys.stdout.flush()

if __name__ == "__main__":
    main() 