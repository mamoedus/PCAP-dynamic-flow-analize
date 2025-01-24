import csv
import os
from collections import defaultdict

def process_csv():
    # Читаем имя входного файла из tmp.txt, которое создает С++ код
    try:
        with open('tmp.txt', 'r') as tmp_file:
            input_file = tmp_file.read().strip()
            inp=str(input_file)
            os.remove("tmp.txt") # Удаляем временны файл
    except FileNotFoundError:
        print("File tmp.txt not found.")
        return
    output_file = inp[:5] + "processed_" + inp[5:]

    # Хранилище для подсчета статистики
    stats = defaultdict(lambda: {"received_packets": 0, "received_bytes": 0, 
                                 "sent_packets": 0, "sent_bytes": 0})

    try:
        # Читаем входной CSV-файл
        with open(input_file, 'r') as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                src_ip = row["Source IP"]
                dst_ip = row["Destination IP"]
                packet_count = int(row["Packet Count"])
                byte_count = int(row["Byte Count"])

                # Обновляем статистику для отправителя
                stats[src_ip]["sent_packets"] += packet_count
                stats[src_ip]["sent_bytes"] += byte_count

                # Обновляем статистику для получателя
                stats[dst_ip]["received_packets"] += packet_count
                stats[dst_ip]["received_bytes"] += byte_count

        # Записываем результаты в выходной CSV-файл
        with open(output_file, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["IP Address", "Received Packets", "Received Bytes", 
                             "Sent Packets", "Sent Bytes"])

            for ip, data in stats.items():
                writer.writerow([ip, data["received_packets"], data["received_bytes"], 
                                 data["sent_packets"], data["sent_bytes"]])

        print(f"Postprocessing completed. Data written to {output_file}.")

    except FileNotFoundError:
        print(f"Input file {input_file} wasnt found")
    except KeyError as e:
        print(f"Error: there is no needed field {e} in input file")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    process_csv()
