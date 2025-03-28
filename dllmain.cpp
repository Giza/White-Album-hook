#include <Windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <cstdio>

// Пишем лог в файл для отладки
void WriteLog(const char* fmt, ...) {
    char buffer[4096];
    va_list args;
    va_start(args, fmt);
    vsprintf_s(buffer, fmt, args);
    va_end(args);

    std::ofstream logfile("WAMemories_hook.log", std::ios::app);
    if (logfile.is_open()) {
        logfile << buffer << std::endl;
        logfile.close();
    }
}

// Байты оригинальной функции для поиска сигнатуры шрифта с маской
// 0xFF - проверяем точное совпадение, 0x00 - пропускаем байт (любое значение)
const unsigned char originalFontBytes[] = { 0xC7, 0x46, 0x30, 0xC0, 0x13, 0x00, 0x00 };
const unsigned char fontBytesMask[] =    { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };

// Байты оригинальной функции для проверки диапазона символов (расширенная сигнатура)
const unsigned char originalRangeBytes[] = { 0x83, 0xF8, 0x20, 0x72, 0x05, 0x83, 0xF8, 0x7E, 0x76, 0x05 };

// Байты для нового хука диапазона
const unsigned char originalRangeBytes2[] = { 0x8D, 0x43, 0xE0, 0x83, 0xF8, 0x5E, 0x77, 0x63 };

// Путь к файлу шрифта - рядом с DLL
const char* fontFilePath = "custom_font.bin";

// Адрес, по которому будут загружены данные шрифта
DWORD g_fontDataAddress = 0;

// Буфер для хранения данных шрифта
std::vector<unsigned char> g_fontData;

// Глобальные переменные для трамплина
unsigned char g_originalBytes[6] = {0}; // Сохраняем оригинальные байты
DWORD g_originalAddress = 0;            // Адрес оригинальной функции
DWORD g_trampolineAddress = 0;          // Адрес трамплина
DWORD g_returnAddress = 0;              // Адрес возврата после трамплина

// Глобальные переменные для второго трамплина
unsigned char g_originalBytes2[6] = {0}; // Сохраняем оригинальные байты второго хука
DWORD g_originalAddress2 = 0;            // Адрес оригинальной функции второго хука
DWORD g_trampolineAddress2 = 0;          // Адрес трамплина второго хука
DWORD g_returnAddress2 = 0;              // Адрес возврата после трамплина второго хука

// Функция трамплина (будет заполнена в рантайме)
// Сигнатура: cmp eax, 0x451; jna +X; [оригинальный код]
unsigned char g_trampolineCode[] = {
    0x3D, 0x91, 0xD1, 0x00, 0x00,  // cmp eax, 0x451
    0x76, 0x05,                    // jna [метка перехода в оригинальный код]
    0xB8, 0x20, 0x00, 0x00, 0x00,  // mov eax, 0x20
    0xE9, 0x00, 0x00, 0x00, 0x00   // jmp [оригинальный адрес возврата]
};

// Функция второго трамплина (будет заполнена в рантайме)
// Сигнатура: cmp eax, 0xD191; ja +X; [оригинальный код для значений в диапазоне]
unsigned char g_trampolineCode2[] = {
    0x3D, 0x91, 0xD1, 0x00, 0x00,  // cmp eax, 0xD191
    0x77, 0x05,                    // ja [метка перехода, если > D191]
    0xE9, 0x00, 0x00, 0x00, 0x00,   // jmp [оригинальный адрес возврата]
    0xE9, 0x00, 0x00, 0x00, 0x00
};

// Получение базового адреса модуля
DWORD GetBaseAddress() {
    return (DWORD)GetModuleHandleA(NULL);
}

// Функция поиска сигнатуры в памяти с использованием маски
DWORD FindSignatureWithMask(const unsigned char* signature, const unsigned char* mask, size_t signatureSize, DWORD startAddress, DWORD endAddress) {
    // Проверяем границы
    if (startAddress >= endAddress || signatureSize == 0) {
        return 0;
    }

    WriteLog("Поиск сигнатуры с маской в диапазоне 0x%08X - 0x%08X", startAddress, endAddress);

    // Поиск сигнатуры в памяти
    for (DWORD addr = startAddress; addr < endAddress - signatureSize; addr++) {
        bool found = true;
        
        // Проверка доступности памяти перед чтением
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
            addr += 4096; // Пропускаем страницу, если не смогли получить информацию
            continue;
        }
        
        // Пропускаем неподходящие регионы памяти
        if (mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
            addr = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1;
            continue;
        }
        
        __try {
            // Проверяем совпадение сигнатуры с учетом маски
            for (size_t i = 0; i < signatureSize; i++) {
                // Если маска байта == 0xFF, то проверяем точное совпадение
                // Если маска байта == 0x00, то пропускаем байт (любое значение)
                if (mask[i] == 0xFF && *(unsigned char*)(addr + i) != signature[i]) {
                    found = false;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            found = false;
            addr = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1; // Пропускаем текущий регион
            continue;
        }
        
        if (found) {
            WriteLog("Сигнатура с маской найдена по адресу 0x%08X", addr);
            return addr;
        }
    }
    
    WriteLog("Сигнатура с маской не найдена");
    return 0;
}

// Функция поиска сигнатуры в памяти
DWORD FindSignature(const unsigned char* signature, size_t signatureSize, DWORD startAddress, DWORD endAddress) {
    // Проверяем границы
    if (startAddress >= endAddress || signatureSize == 0) {
        return 0;
    }

    WriteLog("Поиск сигнатуры в диапазоне 0x%08X - 0x%08X", startAddress, endAddress);

    // Поиск сигнатуры в памяти
    for (DWORD addr = startAddress; addr < endAddress - signatureSize; addr++) {
        bool found = true;
        
        // Проверка доступности памяти перед чтением
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
            addr += 4096; // Пропускаем страницу, если не смогли получить информацию
            continue;
        }
        
        // Пропускаем неподходящие регионы памяти
        if (mbi.State != MEM_COMMIT || mbi.Protect & PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
            addr = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1;
            continue;
        }
        
        __try {
            // Проверяем совпадение сигнатуры
            for (size_t i = 0; i < signatureSize; i++) {
                if (*(unsigned char*)(addr + i) != signature[i]) {
                    found = false;
                    break;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            found = false;
            addr = (DWORD)mbi.BaseAddress + mbi.RegionSize - 1; // Пропускаем текущий регион
            continue;
        }
        
        if (found) {
            WriteLog("Сигнатура найдена по адресу 0x%08X", addr);
            return addr;
        }
    }
    
    WriteLog("Сигнатура не найдена");
    return 0;
}

// Загрузка данных шрифта из файла
bool LoadFontData() {
    try {
        // Создаем полный путь к файлу на основе пути DLL
        char dllPath[MAX_PATH] = {0};
        char fontPath[MAX_PATH] = {0};
        
        GetModuleFileNameA(GetModuleHandleA("WAMemories_Hook.asi"), dllPath, MAX_PATH);
        
        // Находим последний слеш в пути и заменяем имя файла
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) {
            size_t prefixLen = lastSlash - dllPath + 1;
            strncpy_s(fontPath, dllPath, prefixLen);
            strcat_s(fontPath, fontFilePath);
        } else {
            strcpy_s(fontPath, fontFilePath);
        }
        
        WriteLog("Попытка загрузки шрифта из: %s", fontPath);
        
        std::ifstream file(fontPath, std::ios::binary);
        if (!file.is_open()) {
            WriteLog("Не удалось открыть файл: %s", fontPath);
            
            // Пробуем открыть в текущей директории
            file.open(fontFilePath, std::ios::binary);
            if (!file.is_open()) {
                WriteLog("Не удалось открыть файл в текущей директории: %s", fontFilePath);
                return false;
            }
            WriteLog("Файл открыт в текущей директории");
        }

        // Определяем размер файла
        file.seekg(0, std::ios::end);
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        WriteLog("Размер файла шрифта: %zu байт", fileSize);

        if (fileSize == 0) {
            WriteLog("Файл шрифта пуст!");
            return false;
        }

        // Читаем данные в буфер
        g_fontData.resize(fileSize);
        file.read(reinterpret_cast<char*>(g_fontData.data()), fileSize);
        file.close();

        // Выделяем память для данных шрифта с соответствующими правами доступа
        g_fontDataAddress = reinterpret_cast<DWORD>(VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (g_fontDataAddress == 0) {
            WriteLog("Не удалось выделить память для данных шрифта!");
            return false;
        }

        // Копируем данные в выделенную память
        memcpy(reinterpret_cast<void*>(g_fontDataAddress), g_fontData.data(), fileSize);
        
        WriteLog("Данные шрифта загружены в память по адресу: 0x%08X", g_fontDataAddress);
        
        return true;
    }
    catch (const std::exception& e) {
        WriteLog("Исключение при загрузке шрифта: %s", e.what());
        return false;
    }
}

// Функция для создания перехвата шрифта
bool InstallFontHook() {
    try {
        // Получаем актуальный базовый адрес
        DWORD baseAddress = GetBaseAddress();
        WriteLog("Базовый адрес: 0x%08X", baseAddress);
        
        // Ищем сигнатуру в памяти с использованием маски
        DWORD hookAddress = FindSignatureWithMask(originalFontBytes, fontBytesMask, sizeof(originalFontBytes), baseAddress, baseAddress + 0x1000000);
        if (hookAddress == 0) {
            WriteLog("Не удалось найти сигнатуру шрифта в памяти. Попробуем использовать альтернативный поиск.");
            
            // Альтернативный поиск: ищем только первые 3 байта, так как константа может отличаться
            const unsigned char partialSignature[] = { 0xC7, 0x46, 0x30 };
            const unsigned char partialMask[] = { 0xFF, 0xFF, 0xFF };
            hookAddress = FindSignatureWithMask(partialSignature, partialMask, sizeof(partialSignature), baseAddress, baseAddress + 0x1000000);
            
            if (hookAddress == 0) {
                WriteLog("Сигнатуру шрифта не удалось найти даже частично. Хук не может быть установлен.");
                return false;
            }
            
            WriteLog("Найдена частичная сигнатура шрифта по адресу: 0x%08X", hookAddress);
        }
        
        // Выводим байты по адресу для проверки
        unsigned char currentBytes[7] = {0};
        memcpy(currentBytes, reinterpret_cast<void*>(hookAddress), sizeof(currentBytes));
        
        WriteLog("Байты шрифта по найденному адресу 0x%08X: %02X %02X %02X %02X %02X %02X %02X", 
                 hookAddress, 
                 currentBytes[0], currentBytes[1], currentBytes[2], 
                 currentBytes[3], currentBytes[4], currentBytes[5], currentBytes[6]);

        // Снимаем защиту с памяти
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(hookAddress), 7, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("Не удалось снять защиту с памяти для хука шрифта! GetLastError: %d", GetLastError());
            return false;
        }

        // Подготавливаем новую инструкцию: mov [esi+30], g_fontDataAddress
        unsigned char newBytes[7];
        newBytes[0] = 0xC7;      // mov
        newBytes[1] = 0x46;      // [esi+
        newBytes[2] = 0x30;      // 0x30]
        
        // Копируем адрес нашего буфера (little-endian)
        *reinterpret_cast<DWORD*>(&newBytes[3]) = g_fontDataAddress;

        // Записываем новую инструкцию
        WriteLog("Запись новых байтов шрифта: %02X %02X %02X %02X %02X %02X %02X",
                 newBytes[0], newBytes[1], newBytes[2], 
                 newBytes[3], newBytes[4], newBytes[5], newBytes[6]);
        
        memcpy(reinterpret_cast<void*>(hookAddress), newBytes, 7);

        // Восстанавливаем защиту памяти
        DWORD unused;
        if (!VirtualProtect(reinterpret_cast<void*>(hookAddress), 7, oldProtect, &unused)) {
            WriteLog("Не удалось восстановить защиту памяти для хука шрифта! GetLastError: %d", GetLastError());
            // Продолжаем выполнение
        }

        // Проверяем, что байты успешно записаны
        unsigned char verifyBytes[7] = {0};
        memcpy(verifyBytes, reinterpret_cast<void*>(hookAddress), sizeof(verifyBytes));
        
        WriteLog("Байты шрифта после записи: %02X %02X %02X %02X %02X %02X %02X", 
                 verifyBytes[0], verifyBytes[1], verifyBytes[2], 
                 verifyBytes[3], verifyBytes[4], verifyBytes[5], verifyBytes[6]);
        
        if (memcmp(verifyBytes, newBytes, 7) != 0) {
            WriteLog("Не удалось записать новые байты шрифта!");
            return false;
        }
        
        WriteLog("Хук шрифта успешно установлен по адресу: 0x%08X", hookAddress);
        return true;
    }
    catch (const std::exception& e) {
        WriteLog("Исключение при установке хука шрифта: %s", e.what());
        return false;
    }
}

// Функция для создания трамплина и перехвата диапазона символов
bool InstallRangeHook() {
    try {
        // Получаем актуальный базовый адрес
        DWORD baseAddress = GetBaseAddress();
        
        // Ищем сигнатуру для диапазона символов
        DWORD hookAddress = FindSignature(originalRangeBytes, sizeof(originalRangeBytes), baseAddress, baseAddress + 0x1000000);
        if (hookAddress == 0) {
            WriteLog("Не удалось найти сигнатуру диапазона символов в памяти.");
            return false;
        }
        
        WriteLog("Найдена сигнатура диапазона символов по адресу: 0x%08X", hookAddress);
        
        // Находим адрес инструкции cmp eax,7E
        g_originalAddress = hookAddress + 5; // Адрес инструкции cmp eax,7E
        
        // Выводим байты по адресу для проверки
        WriteLog("Адрес инструкции cmp eax,7E: 0x%08X", g_originalAddress);
        
        // Сохраняем оригинальные байты для последующей перезаписи
        memcpy(g_originalBytes, reinterpret_cast<void*>(g_originalAddress), 3);
        
        WriteLog("Оригинальные байты: %02X %02X %02X", 
                 g_originalBytes[0], g_originalBytes[1], g_originalBytes[2]);
        
        // Читаем больше байт для поиска mov ecx, [edx+eax*4-0x80]
        unsigned char codeBytes[20] = {0};
        memcpy(codeBytes, reinterpret_cast<void*>(hookAddress), sizeof(codeBytes));
        
        WriteLog("Байты кода: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                 codeBytes[0], codeBytes[1], codeBytes[2], codeBytes[3], codeBytes[4],
                 codeBytes[5], codeBytes[6], codeBytes[7], codeBytes[8], codeBytes[9],
                 codeBytes[10], codeBytes[11], codeBytes[12], codeBytes[13], codeBytes[14],
                 codeBytes[15], codeBytes[16], codeBytes[17], codeBytes[18], codeBytes[19]);
        
        // Ищем инструкцию mov ecx, [edx+eax*4-0x80] (8B 4C 82 80)
        DWORD movEcxAddress = 0;
        for (int i = 0; i < sizeof(codeBytes) - 4; i++) {
            if (codeBytes[i] == 0x8B && codeBytes[i+1] == 0x4C && codeBytes[i+2] == 0x82 && codeBytes[i+3] == 0x80) {
                movEcxAddress = hookAddress + i;
                WriteLog("Найдена инструкция mov ecx, [edx+eax*4-0x80] по адресу: 0x%08X", movEcxAddress);
                break;
            }
        }
        
        if (movEcxAddress == 0) {
            WriteLog("Не удалось найти инструкцию mov ecx, [edx+eax*4-0x80]!");
            return false;
        }
        
        // Выделяем память для трамплина
        g_trampolineAddress = (DWORD)VirtualAlloc(NULL, sizeof(g_trampolineCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (g_trampolineAddress == 0) {
            WriteLog("Не удалось выделить память для трамплина!");
            return false;
        }
        
        WriteLog("Выделена память для трамплина по адресу: 0x%08X", g_trampolineAddress);
        
        // Изменяем адрес возврата - теперь возвращаемся на mov ecx, [edx+eax*4-0x80]
        g_returnAddress = movEcxAddress;
        
        WriteLog("Новый адрес возврата (на mov ecx, [edx+eax*4-0x80]): 0x%08X", g_returnAddress);
        
        // Подготавливаем код трамплина
        // Заполняем адрес возврата в последней инструкции jmp
        DWORD relativeJump = g_returnAddress - (g_trampolineAddress + sizeof(g_trampolineCode));
        *(DWORD*)(g_trampolineCode + 13) = relativeJump;
        
        // Копируем код трамплина в выделенную память
        memcpy((void*)g_trampolineAddress, g_trampolineCode, sizeof(g_trampolineCode));
        
        WriteLog("Трамплин успешно инициализирован");
        
        // Снимаем защиту с памяти для установки прыжка на трамплин
        DWORD oldProtect;
        if (!VirtualProtect((void*)g_originalAddress, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("Не удалось снять защиту с памяти для хука диапазона! GetLastError: %d", GetLastError());
            return false;
        }
        
        // Создаем инструкцию прыжка на трамплин: jmp [относительный адрес]
        unsigned char jumpCode[5];
        jumpCode[0] = 0xE9; // jmp rel32
        
        // Вычисляем относительный адрес для прыжка
        DWORD relativeAddress = g_trampolineAddress - (g_originalAddress + 5);
        *(DWORD*)(jumpCode + 1) = relativeAddress;
        
        WriteLog("Устанавливаем прыжок на трамплин по адресу 0x%08X: %02X %02X %02X %02X %02X", 
                 g_originalAddress, jumpCode[0], jumpCode[1], jumpCode[2], jumpCode[3], jumpCode[4]);
        
        // Записываем инструкцию прыжка
        memcpy((void*)g_originalAddress, jumpCode, 5);
        
        // Восстанавливаем защиту памяти
        DWORD unused;
        if (!VirtualProtect((void*)g_originalAddress, 5, oldProtect, &unused)) {
            WriteLog("Не удалось восстановить защиту памяти для хука диапазона! GetLastError: %d", GetLastError());
            // Продолжаем выполнение
        }
        
        // Проверяем, что байты успешно записаны
        unsigned char verifyBytes[5];
        memcpy(verifyBytes, (void*)g_originalAddress, 5);
        
        WriteLog("Байты прыжка после записи: %02X %02X %02X %02X %02X", 
                 verifyBytes[0], verifyBytes[1], verifyBytes[2], verifyBytes[3], verifyBytes[4]);
        
        if (verifyBytes[0] != 0xE9) {
            WriteLog("Не удалось записать инструкцию прыжка!");
            return false;
        }
        
        WriteLog("Хук диапазона символов успешно установлен.");
        return true;
    }
    catch (const std::exception& e) {
        WriteLog("Исключение при установке хука диапазона: %s", e.what());
        return false;
    }
}

// Функция для создания трамплина и перехвата второго диапазона символов
bool InstallRangeHook2() {
    try {
        // Получаем актуальный базовый адрес
        DWORD baseAddress = GetBaseAddress();
        
        // Ищем сигнатуру для диапазона символов
        DWORD hookAddress = FindSignature(originalRangeBytes2, sizeof(originalRangeBytes2), baseAddress, baseAddress + 0x1000000);
        if (hookAddress == 0) {
            WriteLog("Не удалось найти сигнатуру второго диапазона символов в памяти.");
            return false;
        }
        
        WriteLog("Найдена сигнатура второго диапазона символов по адресу: 0x%08X", hookAddress);
        
        // Находим адрес инструкции cmp eax,5E (смещение 3 от начала сигнатуры)
        g_originalAddress2 = hookAddress + 3; // Адрес инструкции cmp eax,5E
        
        // Выводим байты по адресу для проверки
        unsigned char currentBytes[5] = {0};
        memcpy(currentBytes, reinterpret_cast<void*>(g_originalAddress2), sizeof(currentBytes));
        
        WriteLog("Найден код по адресу 0x%08X: %02X %02X %02X %02X %02X", 
                 g_originalAddress2, currentBytes[0], currentBytes[1], currentBytes[2],
                 currentBytes[3], currentBytes[4]);
        
        // Проверяем, что это действительно cmp eax,5E и ja +XX
        if (currentBytes[0] != 0x83 || currentBytes[1] != 0xF8 || currentBytes[2] != 0x5E || 
            currentBytes[3] != 0x77) {
            WriteLog("Ожидалась последовательность cmp eax,5E; ja +XX (83 F8 5E 77 XX), но найдено: %02X %02X %02X %02X %02X", 
                     currentBytes[0], currentBytes[1], currentBytes[2], currentBytes[3], currentBytes[4]);
            return false;
        }
        
        // Читаем больше байт для анализа
        unsigned char codeBytes[30] = {0};
        memcpy(codeBytes, reinterpret_cast<void*>(hookAddress), sizeof(codeBytes));
        
        WriteLog("Байты кода второго хука (первые 20 байт): %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                 codeBytes[0], codeBytes[1], codeBytes[2], codeBytes[3], codeBytes[4],
                 codeBytes[5], codeBytes[6], codeBytes[7], codeBytes[8], codeBytes[9],
                 codeBytes[10], codeBytes[11], codeBytes[12], codeBytes[13], codeBytes[14],
                 codeBytes[15], codeBytes[16], codeBytes[17], codeBytes[18], codeBytes[19]);
        
        // Сохраняем оригинальные байты для последующей перезаписи
        memcpy(g_originalBytes2, reinterpret_cast<void*>(g_originalAddress2), 5);
        
        WriteLog("Оригинальные байты второго хука (5 байт): %02X %02X %02X %02X %02X", 
                g_originalBytes2[0], g_originalBytes2[1], g_originalBytes2[2],
                g_originalBytes2[3], g_originalBytes2[4]);
        
        // Устанавливаем адрес возврата на инструкцию lea eax,[esp+14]
        // Смещение = 3 байта (cmp) + 2 байта (ja +XX) = 5 байт
        // Исправляем адрес возврата - прибавляем +1 байт, чтобы попасть точно на lea eax,[esp+14]
        g_returnAddress2 = g_originalAddress2 + 5 + 1; // Добавляем +1 для коррекции
        
        WriteLog("Адрес возврата для второго хука: 0x%08X (скорректированный)", g_returnAddress2);
        
        // Для отладки читаем байты по адресу возврата
        unsigned char returnBytes[5] = {0};
        memcpy(returnBytes, reinterpret_cast<void*>(g_returnAddress2), sizeof(returnBytes));
        
        WriteLog("Байты по адресу возврата 0x%08X: %02X %02X %02X %02X %02X", 
                 g_returnAddress2, returnBytes[0], returnBytes[1], returnBytes[2],
                 returnBytes[3], returnBytes[4]);
        
        // Выделяем память для трамплина
        g_trampolineAddress2 = (DWORD)VirtualAlloc(NULL, sizeof(g_trampolineCode2), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (g_trampolineAddress2 == 0) {
            WriteLog("Не удалось выделить память для второго трамплина!");
            return false;
        }
        
        WriteLog("Выделена память для второго трамплина по адресу: 0x%08X", g_trampolineAddress2);
        
        // Получаем значение смещения из оригинальной инструкции ja XX
        signed char jaOffset = 0x63; // Это значение из оригинального кода (77 63)
        DWORD jaTargetAddress = g_originalAddress2 + 5 + jaOffset; // адрес следующей инструкции + смещение

        WriteLog("Адрес инструкции ja: 0x%08X", g_originalAddress2);
        WriteLog("Смещение ja: 0x%02X (%d)", (unsigned char)jaOffset, (int)jaOffset);
        WriteLog("Вычисленный адрес назначения ja: 0x%08X", jaTargetAddress);

        // Подготавливаем код трамплина
        // Заполняем адрес возврата в первой инструкции jmp
        DWORD relativeJump = g_returnAddress2 - (g_trampolineAddress2 + 13);
        *(DWORD*)(g_trampolineCode2 + 8) = relativeJump;

        // Заполняем адрес для ja во второй инструкции jmp
        DWORD jaJump = jaTargetAddress - (g_trampolineAddress2 + 18);
        *(DWORD*)(g_trampolineCode2 + 13) = jaJump;
        
        // Копируем код трамплина в выделенную память
        memcpy((void*)g_trampolineAddress2, g_trampolineCode2, sizeof(g_trampolineCode2));
        
        WriteLog("Второй трамплин успешно инициализирован");
        
        // Снимаем защиту с памяти для установки прыжка на трамплин
        DWORD oldProtect;
        if (!VirtualProtect((void*)g_originalAddress2, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            WriteLog("Не удалось снять защиту с памяти для второго хука! GetLastError: %d", GetLastError());
            return false;
        }
        
        // Создаем инструкцию прыжка на трамплин: jmp [относительный адрес]
        unsigned char jumpCode[5];
        jumpCode[0] = 0xE9; // jmp rel32
        
        // Вычисляем относительный адрес для прыжка
        DWORD relativeAddress = g_trampolineAddress2 - (g_originalAddress2 + 5);
        *(DWORD*)(jumpCode + 1) = relativeAddress;
        
        WriteLog("Устанавливаем прыжок на второй трамплин по адресу 0x%08X: %02X %02X %02X %02X %02X", 
                g_originalAddress2, jumpCode[0], jumpCode[1], jumpCode[2], jumpCode[3], jumpCode[4]);
        
        // Записываем инструкцию прыжка
        memcpy((void*)g_originalAddress2, jumpCode, 5);
        
        // Восстанавливаем защиту памяти
        DWORD unused;
        if (!VirtualProtect((void*)g_originalAddress2, 5, oldProtect, &unused)) {
            WriteLog("Не удалось восстановить защиту памяти для второго хука! GetLastError: %d", GetLastError());
            // Продолжаем выполнение
        }
        
        // Проверяем, что байты успешно записаны
        unsigned char verifyBytes[5];
        memcpy(verifyBytes, (void*)g_originalAddress2, 5);
        
        WriteLog("Байты прыжка второго хука после записи: %02X %02X %02X %02X %02X", 
                verifyBytes[0], verifyBytes[1], verifyBytes[2], verifyBytes[3], verifyBytes[4]);
        
        if (verifyBytes[0] != 0xE9) {
            WriteLog("Не удалось записать инструкцию прыжка для второго хука!");
            return false;
        }
        
        WriteLog("Второй хук диапазона символов успешно установлен.");
        return true;
    }
    catch (const std::exception& e) {
        WriteLog("Исключение при установке второго хука диапазона: %s", e.what());
        return false;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        
        // Очистка лога при запуске
        {
            std::ofstream logfile("WAMemories_hook.log");
            logfile.close();
        }
        
        WriteLog("DLL загружена в процесс");
        
        // Добавляем задержку, чтобы убедиться, что игра полностью загрузилась
        Sleep(1000);
        
        // Загружаем данные шрифта
        if (!LoadFontData()) {
            WriteLog("Ошибка при загрузке шрифта");
            MessageBoxA(NULL, "Не удалось загрузить файл шрифта. Проверьте лог.", "WAMemories Hook", MB_ICONERROR);
            return TRUE; // Продолжаем работу, даже если не удалось загрузить шрифт
        }
        
        // Устанавливаем хук шрифта
        if (!InstallFontHook()) {
            WriteLog("Ошибка при установке хука шрифта");
            MessageBoxA(NULL, "Не удалось установить хук шрифта. Проверьте лог.", "WAMemories Hook", MB_ICONERROR);
            return TRUE; // Продолжаем работу, даже если не удалось установить хук
        }
        
        // Устанавливаем хук диапазона символов
        if (!InstallRangeHook()) {
            WriteLog("Ошибка при установке хука диапазона символов");
            MessageBoxA(NULL, "Не удалось установить хук диапазона символов. Проверьте лог.", "WAMemories Hook", MB_ICONERROR);
            return TRUE; // Продолжаем работу, даже если не удалось установить хук
        }
        
        // Устанавливаем второй хук диапазона символов
        if (!InstallRangeHook2()) {
            WriteLog("Ошибка при установке второго хука диапазона символов");
            MessageBoxA(NULL, "Не удалось установить второй хук диапазона символов. Проверьте лог.", "WAMemories Hook", MB_ICONERROR);
            return TRUE; // Продолжаем работу, даже если не удалось установить хук
        }
        
        WriteLog("Инициализация DLL завершена успешно");
        break;
        
    case DLL_PROCESS_DETACH:
        // Восстанавливаем оригинальные байты, если они были сохранены
        if (g_originalAddress != 0 && g_originalBytes[0] != 0) {
            DWORD oldProtect;
            if (VirtualProtect((void*)g_originalAddress, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy((void*)g_originalAddress, g_originalBytes, 3);
                VirtualProtect((void*)g_originalAddress, 3, oldProtect, &oldProtect);
                WriteLog("Восстановлены оригинальные байты первого хука");
            }
        }
        
        // Восстанавливаем оригинальные байты второго хука
        if (g_originalAddress2 != 0 && g_originalBytes2[0] != 0) {
            DWORD oldProtect;
            if (VirtualProtect((void*)g_originalAddress2, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy((void*)g_originalAddress2, g_originalBytes2, 5);
                VirtualProtect((void*)g_originalAddress2, 5, oldProtect, &oldProtect);
                WriteLog("Восстановлены оригинальные байты второго хука");
            }
        }

        // Освобождаем выделенную память для трамплинов
        if (g_trampolineAddress != 0) {
            VirtualFree((void*)g_trampolineAddress, 0, MEM_RELEASE);
            WriteLog("Память для первого трамплина освобождена");
        }
        
        if (g_trampolineAddress2 != 0) {
            VirtualFree((void*)g_trampolineAddress2, 0, MEM_RELEASE);
            WriteLog("Память для второго трамплина освобождена");
        }
        
        // Освобождаем выделенную память для шрифта
        if (g_fontDataAddress != 0) {
            VirtualFree(reinterpret_cast<void*>(g_fontDataAddress), 0, MEM_RELEASE);
            WriteLog("Память для шрифта освобождена");
        }
        
        WriteLog("DLL выгружена из процесса");
        break;
    }
    
    return TRUE;
} 