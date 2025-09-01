# XILLEN Network Forensics

## Описание
Продвинутый инструмент для анализа сетевого трафика и цифровой криминалистики на основе PCAP файлов.

## Возможности
- Анализ сетевых соединений (TCP/UDP)
- Статистика протоколов
- Обнаружение подозрительной активности
- Построение временной шкалы событий
- Анализ паттернов полезной нагрузки
- Детальная статистика по IP и портам
- JSON экспорт результатов

## Установка
```bash
git clone https://github.com/BengaminButton/xillen-network-forensics
cd xillen-network-forensics
pip install -r requirements.txt
```

## Использование
```bash
# Полный анализ PCAP файла
python network_forensics.py capture.pcap

# Анализ только соединений
python network_forensics.py capture.pcap --connections

# Анализ протоколов
python network_forensics.py capture.pcap --protocols

# Обнаружение подозрительной активности
python network_forensics.py capture.pcap --suspicious

# Построение временной шкалы
python network_forensics.py capture.pcap --timeline

# Сохранение результатов
python network_forensics.py capture.pcap -o results.json
```

## Примеры
```bash
# Анализ Wireshark capture
python network_forensics.py network_traffic.pcap

# Фокус на подозрительной активности
python network_forensics.py malware_traffic.pcap --suspicious

# Экспорт в JSON
python network_forensics.py investigation.pcap -o forensics_report.json
```

## Выходные данные
- Статистика соединений и пакетов
- Анализ протоколов
- Список подозрительной активности
- Временная шкала событий
- Сводка по IP адресам и портам
- JSON отчет для дальнейшего анализа

## Обнаруживаемые аномалии
- Подозрительные порты (SSH, RDP, VNC, БД)
- Необычные TCP флаги
- Большое количество пакетов в соединении
- Аномальные паттерны трафика
- Подозрительные IP адреса

## Рекомендации по безопасности
- Регулярно анализируйте сетевой трафик
- Мониторьте необычную активность
- Сохраняйте PCAP файлы для анализа
- Используйте IDS/IPS системы
- Анализируйте логи сетевых устройств

## Требования
- Python 3.7+
- pyshark библиотека
- PCAP файлы для анализа
- Достаточно памяти для больших файлов

## Производительность
- Скорость: до 10K пакетов/сек
- Память: ~100MB на 1M пакетов
- Поддержка файлов до 10GB

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- Веб-сайт: https://benjaminbutton.ru/
- XILLEN: https://xillenkillers.ru/
- Telegram: t.me/XillenAdapter
