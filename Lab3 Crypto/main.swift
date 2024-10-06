import Foundation
import CryptoKit
import Security

class SecureDataStorage {
    private var symmetricKey: SymmetricKey?  // Симметричный ключ для шифрования/дешифрования
    private var encryptedDataStore: [Data] = []  // Массив для хранения зашифрованных данных

    // Инициализация объекта: генерация ключа и шифрование строк
    init() {
        generateAndStoreKey()  // Генерация ключа
        storeEncryptedStrings()  // Шифрование строк и их сохранение
    }

    // Генерация симметричного ключа для использования при шифровании и дешифровании
    private func generateAndStoreKey() {
        // Генерация ключа AES-256 для шифрования/дешифрования
        symmetricKey = SymmetricKey(size: .bits256)
    }

    // Метод для шифрования и сохранения строк в зашифрованном виде
    private func storeEncryptedStrings() {
        // Массив исходных строк, которые будут зашифрованы и сохранены
        let originalStrings = [
            "Быстрая коричневая лиса прыгает через ленивую собаку.",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.", // Оставлено как заглушка
            "В криптографии шифрование — это процесс кодирования сообщений или информации таким образом, чтобы их могли прочитать только авторизованные стороны.",
            "История криптографии насчитывает тысячи лет, одним из первых и самых простых методов шифрования был шифр Цезаря.",
            "Современная криптография основана на сложных математических алгоритмах, таких как RSA и AES, которые обеспечивают безопасную связь через интернет.",
            "Шифрование данных жизненно важно для защиты конфиденциальной информации в современном цифровом мире, особенно в условиях роста кибератак.",
            "Криптография с открытым ключом основывается на парах ключей: открытом ключе, который можно передавать публично, и закрытом ключе, который должен оставаться в секрете.",
            "Технология блокчейн использует криптографические методы для обеспечения безопасности и неизменности транзакций.",
            "Квантовые вычисления рассматриваются как угроза и возможность для криптографии, поскольку они могут нарушить существующие методы шифрования, но также предложить новые подходы к защите данных.",
            "Специалисты по кибербезопасности должны постоянно адаптироваться к новым угрозам, и шифрование является одним из их самых мощных инструментов."
        ]

        // Цикл для шифрования каждой строки из массива
        for string in originalStrings {
            // Преобразование строки в данные (Data)
            guard let data = string.data(using: .utf8) else { continue }
            // Шифрование данных и добавление их в хранилище
            _ = encryptAndStore(data: data)
        }
    }

    // Метод для шифрования данных и их сохранения в зашифрованное хранилище
    func encryptAndStore(data: Data) -> Bool {
        // Проверка наличия ключа для шифрования
        guard let key = symmetricKey else { return false }
        do {
            // Шифрование данных с использованием AES-GCM
            let sealedBox = try AES.GCM.seal(data, using: key)
            // Сохранение зашифрованных данных в хранилище
            encryptedDataStore.append(sealedBox.combined!)
            return true
        } catch {
            print("Ошибка шифрования: \(error)")
            return false
        }
    }

    // Метод для расшифровки данных из зашифрованного хранилища
    func decrypt(data: Data) -> Data? {
        // Проверка наличия ключа для дешифрования
        guard let key = symmetricKey, let box = try? AES.GCM.SealedBox(combined: data) else { return nil }
        // Расшифровка данных
        return try? AES.GCM.open(box, using: key)
    }

    // Метод для получения строки по её индексу в зашифрованном хранилище
    func getString(at index: Int) -> String? {
        // Проверка, что индекс находится в пределах массива
        guard index < encryptedDataStore.count else {
            print("Недействительный индекс")
            return nil
        }

        // Извлечение зашифрованных данных по индексу
        let encryptedData = encryptedDataStore[index]

        // Расшифровка данных и преобразование их обратно в строку
        if let decryptedData = decrypt(data: encryptedData),
           let decryptedString = String(data: decryptedData, encoding: .utf8) {
            return decryptedString
        } else {
            print("Не удалось расшифровать данные")
            return nil
        }
    }
}

// Класс AppDelegate, который управляет запуском программы
class AppDelegate {
    func applicationDidFinishLaunching() {
        let secureStorage = SecureDataStorage()
        
        // Чтение индекса от пользователя для расшифровки строки
        print("Введите индекс строки для расшифровки:")
        if let input = readLine(), let index = Int(input) {
            // Запрашиваем строку по введённому индексу и выводим её на экран
            if let decryptedString = secureStorage.getString(at: index) {
                print("Расшифрованная строка: \(decryptedString)")
            } else {
                print("Не удалось получить строку.")
            }
        } else {
            print("Недопустимый ввод.")
        }
    }
}

// Основная функция, запускающая программу
func main() {
    let appDelegate = AppDelegate()
    appDelegate.applicationDidFinishLaunching()
}

main()
