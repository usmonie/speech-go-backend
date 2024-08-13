# Протокол безопасного обмена сообщениями в распределенной сети

## Оглавление
1. [Введение](#1-введение)
2. [Архитектура системы](#2-архитектура-системы)
3. [Криптографические примитивы](#3-криптографические-примитивы)
4. [Идентификация и аутентификация](#4-идентификация-и-аутентификация)
5. [Управление ключами](#5-управление-ключами)
6. [Хранение и распределение данных](#6-хранение-и-распределение-данных)
7. [Сетевое взаимодействие](#7-сетевое-взаимодействие)
8. [Обмен сообщениями](#8-обмен-сообщениями)
9. [Групповые чаты](#9-групповые-чаты)
10. [Файлы и медиа-контент](#10-файлы-и-медиа-контент)
11. [Синхронизация устройств](#11-синхронизация-устройств)
12. [Восстановление аккаунта](#12-восстановление-аккаунта)
13. [Безопасность и приватность](#13-безопасность-и-приватность)
14. [Масштабируемость и производительность](#14-масштабируемость-и-производительность)
15. [Аудит и прозрачность](#15-аудит-и-прозрачность)
16. [Обновление и расширение протокола](#16-обновление-и-расширение-протокола)
17. [Соответствие юридическим требованиям](#17-соответствие-юридическим-требованиям)

## 1. Введение

Данный протокол описывает систему безопасного обмена сообщениями, основанную на распределенной сети без централизованных серверов. Ключевые особенности протокола:

- Полностью распределенная архитектура
- Высокий уровень безопасности и приватности
- Сквозное шифрование всех данных
- Поддержка как выделенных серверов, так и пользовательских устройств в качестве узлов сети
- Устойчивость к цензуре и отказам отдельных узлов
- Масштабируемость и эффективность работы при большом количестве пользователей

## 2. Архитектура системы

### 2.1 Компоненты системы

1. Узлы сети
    - Полные узлы: хранят и обрабатывают данные, участвуют в консенсусе
    - Легкие узлы: только отправляют и получают сообщения
    - Суперузлы: выделенные серверы с высокой пропускной способностью

2. Распределенная хеш-таблица (DHT)
    - Используется для поиска узлов и маршрутизации сообщений
    - Хранит метаданные о расположении зашифрованных данных

3. Система распределенного хранения
    - Использует избыточное кодирование для распределения данных между узлами

4. Протокол консенсуса
    - Обеспечивает согласованность состояния сети между узлами

5. Криптографический модуль
    - Реализует все криптографические операции

6. Клиентское программное обеспечение
    - Интерфейс пользователя
    - Локальное хранилище ключей и данных

### 2.2 Взаимодействие компонентов

1. Клиент инициирует операции (отправка сообщения, обновление профиля и т.д.)
2. Криптографический модуль шифрует данные
3. Система распределенного хранения разбивает и распределяет зашифрованные данные
4. DHT обновляется с информацией о расположении данных
5. Протокол консенсуса обеспечивает согласованность DHT между узлами
6. Узлы сети обрабатывают запросы на хранение и извлечение данных
## 3. Криптографические примитивы

### 3.1 Асимметричное шифрование
- Алгоритм: EdDSA с кривой Ed521
- Использование: цифровые подписи, обмен ключами
- Размер ключа: 521 бит

### 3.2 Симметричное шифрование
- Алгоритм: AES-256 в режиме GCM (Galois/Counter Mode)
- Использование: шифрование сообщений и файлов
- Размер ключа: 256 бит

### 3.3 Хеширование
- Алгоритм: SHA3-256
- Использование: целостность данных, генерация идентификаторов

### 3.4 Ключевой обмен
- Протокол: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) на кривой Ed521
- Использование: установка начального общего секрета

### 3.5 Протокол обмена сообщениями
- Алгоритм: Double Ratchet (адаптированный для использования с Ed521)
- Использование: обеспечение forward secrecy и break-in recovery

### 3.6 Постквантовое шифрование
- Алгоритм: Kyber1024 (постквантовый алгоритм на основе решетки)
- Использование: защита от квантовых атак

### 3.7 Постквантовые цифровые подписи
- Алгоритм: Dilithium3 (постквантовый алгоритм цифровой подписи)
- Использование: долгосрочная защита целостности и аутентичности данных

### 3.8 Генерация ключей
- Алгоритм: Argon2id
- Использование: генерация ключей из паролей

### 3.9 Разделение секрета
- Алгоритм: Shamir's Secret Sharing (SSS)
- Использование: распределение ключей для восстановления

### 3.10 Гибридное шифрование
- Комбинация классических (Ed521) и постквантовых (Kyber1024) алгоритмов
- Использование: обеспечение долгосрочной безопасности с сохранением эффективности

Обновление других разделов протокола с учетом новых криптографических примитивов:

## 4. Идентификация и аутентификация

### 4.1 Идентификатор пользователя
1. Генерация долгосрочной пары ключей:
   ```
   identity_key_pair = Ed521.generateKeyPair()
   ```
2. Вычисление идентификатора:
   ```
   user_id = SHA3-256(identity_key_pair.public_key)
   ```

### 4.2 Регистрация в сети
1. Создание запроса на регистрацию:
   ```
   registration_request = {
     "user_id": user_id,
     "public_key": identity_key_pair.public_key,
     "kyber_public_key": kyber_key_pair.public_key,
     "dilithium_public_key": dilithium_key_pair.public_key,
     "signature": Ed521.sign(identity_key_pair.private_key, user_id + kyber_public_key + dilithium_public_key),
     "timestamp": current_time()
   }
   ```

## 5. Управление ключами

### 5.1 Иерархия ключей
1. Корневой ключ (Root Key)
    - Генерируется при создании аккаунта
    - Используется для деривации других ключей
2. Ключ идентичности Ed521 (Ed521 Identity Key)
    - Долгосрочный ключ для идентификации пользователя
3. Ключ Kyber1024 (Kyber1024 Key)
    - Используется для постквантового шифрования
4. Ключ Dilithium3 (Dilithium3 Signing Key)
    - Используется для постквантовых цифровых подписей
5. Ключи сессий (Session Keys)
    - Краткосрочные ключи для шифрования сообщений

### 5.2 Генерация и хранение ключей
1. Генерация корневого ключа:
   ```
   root_key = SecureRandom.generateBytes(32)
   ```
2. Деривация других ключей:
   ```
   ed521_seed = HKDF-SHA3-256(root_key, "ed521", 66)
   kyber_seed = HKDF-SHA3-256(root_key, "kyber", 32)
   dilithium_seed = HKDF-SHA3-256(root_key, "dilithium", 32)
   
   ed521_key_pair = Ed521.generateKeyPair(ed521_seed)
   kyber_key_pair = Kyber1024.generateKeyPair(kyber_seed)
   dilithium_key_pair = Dilithium3.generateKeyPair(dilithium_seed)
   ```

## 6. Хранение и распределение данных

### 6.1 Шифрование данных
1. Генерация уникального ключа для каждого элемента данных:
   ```
   data_key = SecureRandom.generateBytes(32)
   ```
2. Шифрование данных:
   ```
   encrypted_data = AES-256-GCM.encrypt(data_key, plaintext)
   ```

### 6.2 Гибридное шифрование ключей
1. Шифрование data_key с использованием Ed521 и Kyber1024:
   ```
   ed521_encrypted_key = Ed521.encrypt(recipient_ed521_public_key, data_key)
   kyber_encrypted_key = Kyber1024.encrypt(recipient_kyber_public_key, data_key)
   ```
2. Объединение зашифрованных ключей:
   ```
   hybrid_encrypted_key = ed521_encrypted_key + kyber_encrypted_key
   ```
## 7. Сетевое взаимодействие

### 7.1 Обнаружение узлов
1. Новый узел подключается к известным начальным узлам.
2. Узел запрашивает список других узлов и обновляет свою маршрутизационную таблицу.
3. Для каждого узла хранится:
   ```
   node_info = {
     "node_id": SHA3-256(node_public_key),
     "ed521_public_key": node_ed521_public_key,
     "kyber_public_key": node_kyber_public_key,
     "dilithium_public_key": node_dilithium_public_key,
     "ip_address": node_ip_address,
     "last_seen": timestamp
   }
   ```

### 7.2 Установка защищенного соединения
1. Инициатор генерирует эфемерные ключи:
   ```
   ephemeral_ed521 = Ed521.generateKeyPair()
   ephemeral_kyber = Kyber1024.generateKeyPair()
   ```
2. Отправка предложения соединения:
   ```
   connection_proposal = {
     "initiator_id": initiator_id,
     "ed521_ephemeral_public": ephemeral_ed521.public_key,
     "kyber_ephemeral_public": ephemeral_kyber.public_key,
     "timestamp": current_time(),
     "signature": Dilithium3.sign(initiator_dilithium_private_key, 
                                  initiator_id + ephemeral_ed521.public_key + 
                                  ephemeral_kyber.public_key + timestamp)
   }
   ```
3. Получатель проверяет подпись и генерирует свои эфемерные ключи.
4. Вычисление общих секретов:
   ```
   ed521_shared_secret = ECDHE(initiator_ephemeral_ed521, recipient_ephemeral_ed521)
   kyber_shared_secret = Kyber1024.decapsulate(initiator_ephemeral_kyber, recipient_kyber_private)
   ```
5. Комбинирование общих секретов:
   ```
   combined_shared_secret = SHA3-256(ed521_shared_secret + kyber_shared_secret)
   ```
6. Генерация сессионных ключей:
   ```
   encryption_key = HKDF-SHA3-256(combined_shared_secret, "encryption", 32)
   mac_key = HKDF-SHA3-256(combined_shared_secret, "mac", 32)
   ```

## 8. Обмен сообщениями

### 8.1 Инициализация чата
1. Алиса запрашивает `PreKeyBundle` Боба:
   ```
   PreKeyBundle = {
     "user_id": bob_id,
     "ed521_identity_key": bob_ed521_identity_public_key,
     "ed521_signed_prekey": bob_ed521_signed_prekey_public,
     "ed521_prekey_signature": bob_ed521_prekey_signature,
     "kyber_identity_key": bob_kyber_identity_public_key,
     "kyber_signed_prekey": bob_kyber_signed_prekey_public,
     "kyber_prekey_signature": bob_dilithium_prekey_signature,
     "one_time_prekey": bob_one_time_prekey_public  // может быть null
   }
   ```
2. Алиса проверяет подписи с использованием Dilithium3.
3. Алиса выполняет X3DH с Ed521 и Kyber1024:
   ```
   ed521_dh1 = ECDHE(alice_ed521_identity, bob_ed521_signed_prekey)
   ed521_dh2 = ECDHE(alice_ed521_ephemeral, bob_ed521_identity)
   ed521_dh3 = ECDHE(alice_ed521_ephemeral, bob_ed521_signed_prekey)
   ed521_dh4 = ECDHE(alice_ed521_ephemeral, bob_ed521_one_time_prekey)  // если доступен
   
   kyber_ss1 = Kyber1024.encapsulate(bob_kyber_identity)
   kyber_ss2 = Kyber1024.encapsulate(bob_kyber_signed_prekey)
   ```
4. Вычисление общего секрета:
   ```
   shared_secret = SHA3-256(ed521_dh1 + ed521_dh2 + ed521_dh3 + ed521_dh4 + kyber_ss1 + kyber_ss2)
   ```

### 8.2 Протокол Double Ratchet (адаптированный для Ed521 и Kyber1024)
1. Инициализация состояния Double Ratchet с `shared_secret`.
2. Для каждого сообщения:
    - Обновление ключей отправки с использованием Ed521 ECDHE.
    - Обновление ключей приема при получении нового ratchet-ключа.
    - Периодическое обновление Kyber1024 ключей для постквантовой безопасности.

### 8.3 Шифрование сообщения
1. Генерация ключа сообщения из текущего состояния Double Ratchet.
2. Шифрование сообщения:
   ```
   nonce = SecureRandom.generateBytes(12)
   ciphertext = AES-256-GCM.encrypt(message_key, nonce, plaintext)
   ```
3. Формирование заголовка сообщения:
   ```
   header = {
     "sender_id": alice_id,
     "ed521_ratchet_key": current_ed521_ratchet_public_key,
     "kyber_ratchet_key": current_kyber_ratchet_public_key,
     "prev_chain_length": previous_chain_length,
     "message_number": message_number,
     "nonce": nonce
   }
   ```
4. Подпись сообщения:
   ```
   message_signature = Dilithium3.sign(alice_dilithium_private_key, header + ciphertext)
   ```

### 8.4 Отправка сообщения
1. Формирование пакета сообщения:
   ```
   message_package = {
     "header": header,
     "ciphertext": ciphertext,
     "signature": message_signature
   }
   ```
2. Отправка пакета через сеть (см. раздел 6 о хранении и распределении данных).

### 8.5 Получение сообщения
1. Извлечение пакета сообщения из сети.
2. Проверка подписи с использованием Dilithium3.
3. Обновление состояния Double Ratchet на основе полученных ratchet-ключей.
4. Генерация ключа сообщения из обновленного состояния.
5. Расшифровка сообщения:
   ```
   plaintext = AES-256-GCM.decrypt(message_key, nonce, ciphertext)
   ```

## 9. Групповые чаты

### 9.1 Создание группы
1. Генерация группового идентификатора и ключа:
   ```
   group_id = SHA3-256(creator_id + timestamp)
   group_key = SecureRandom.generateBytes(32)
   ```
2. Создание метаданных группы:
   ```
   group_metadata = {
     "id": group_id,
     "name": group_name,
     "creator": creator_id,
     "members": [member_id for member in members],
     "created_at": timestamp,
     "ed521_public_key": group_ed521_public_key,
     "kyber_public_key": group_kyber_public_key
   }
   ```
3. Подпись метаданных группы:
   ```
   group_metadata_signature = Dilithium3.sign(creator_dilithium_private_key, group_metadata)
   ```
4. Шифрование группового ключа для каждого участника с использованием гибридного шифрования (Ed521 + Kyber1024).

### 9.2 Отправка группового сообщения
1. Генерация ключа сообщения:
   ```
   message_key = HKDF-SHA3-256(group_key, "message" + message_number, 32)
   ```
2. Шифрование сообщения:
   ```
   nonce = SecureRandom.generateBytes(12)
   ciphertext = AES-256-GCM.encrypt(message_key, nonce, plaintext)
   ```
3. Формирование заголовка сообщения и подпись:
   ```
   header = {
     "group_id": group_id,
     "sender_id": sender_id,
     "message_number": message_number,
     "nonce": nonce,
     "timestamp": current_time()
   }
   message_signature = Dilithium3.sign(sender_dilithium_private_key, header + ciphertext)
   ```

### 9.3 Обновление групповых ключей
1. Генерация нового группового ключа.
2. Создание сообщения об обновлении ключа, зашифрованного для каждого участника.
3. Распространение обновления через сеть.
4. Участники обновляют свое локальное состояние группы.

## 10. Файлы и медиа-контент

### 10.1 Шифрование файлов
1. Генерация уникального ключа файла:
   ```
   file_key = SecureRandom.generateBytes(32)
   ```
2. Шифрование файла с использованием AES-256-GCM.
3. Разделение зашифрованного файла на фрагменты с использованием схемы разделения секрета.

### 10.2 Передача файлов
1. Загрузка зашифрованных фрагментов файла в сеть.
2. Создание метаданных файла, включая расположение фрагментов и хеш-сумму SHA3-256.
3. Шифрование ключа файла для получателей с использованием их Ed521 и Kyber1024 публичных ключей.
4. Отправка метаданных файла и зашифрованного ключа через обычный канал сообщений.
