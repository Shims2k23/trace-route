import socket
import struct
import time
import sys

ICMP_ECHO_REQUEST = 8  # ICMP запрос эхо (ping)
ICMP_TIME_EXCEEDED = 11  # TTL истек
ICMP_DEST_UNREACH = 3  # Хост недоступен


def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = (source_string[count + 1] << 8) + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count += 2
    if count_to < len(source_string):
        sum = sum + source_string[count]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    return ~sum & 0xffff


def create_icmp_packet(id, seq):
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, id, seq)
    data = struct.pack("d", time.time())
    checksum_value = checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum_value, id, seq)
    return header + data


def traceroute(target, max_hops=30, timeout=2, packets_per_ttl=3, max_consecutive_timeouts=10):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Ошибка: не удалось разрешить имя хоста {target}")
        return

    print(f"Traceroute to {target} ({target_ip}), {max_hops} hops max, {timeout * 1000} ms timeout\n")

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(timeout)
    except PermissionError:
        print("Ошибка: запустите программу с правами администратора (root)")
        return
    except Exception as e:
        print(f"Ошибка при создании сокетов: {e}")
        return

    packet_id = id(target_ip) & 0xffff
    global_seq = 0
    consecutive_timeouts = 0

    try:
        for ttl in range(1, max_hops + 1):
            try:
                send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            except Exception as e:
                print(f"Ошибка при создании UDP-сокета: {e}")
                break

            times = []
            ips = set()
            timeout_count = 0

            for _ in range(packets_per_ttl):
                global_seq += 1
                try:
                    send_time = time.time()
                    send_socket.sendto(b"", (target_ip, 33434))

                    data, addr = recv_socket.recvfrom(1024)
                    recv_time = time.time()
                    elapsed = (recv_time - send_time) * 1000

                    icmp_header = data[20:28]
                    icmp_type, _, _, _, _ = struct.unpack("!BBHHH", icmp_header)

                    if icmp_type == ICMP_TIME_EXCEEDED:
                        ips.add(addr[0])
                        times.append(f"{elapsed:.2f} ms")
                    elif icmp_type == ICMP_DEST_UNREACH and addr[0] == target_ip:
                        ips.add(addr[0])
                        times.append(f"{elapsed:.2f} ms")
                        print(f"{ttl:<4} {addr[0]:<15} {' '.join(times)} (target reached)")
                        send_socket.close()
                        recv_socket.close()
                        return
                    else:
                        times.append("*")

                except socket.timeout:
                    times.append("*")
                    timeout_count += 1
                except Exception as e:
                    print(f"Ошибка на хопе {ttl}: {e}")
                    times.append("*")

            if timeout_count == packets_per_ttl:
                consecutive_timeouts += 1
            else:
                consecutive_timeouts = 0

            if consecutive_timeouts >= max_consecutive_timeouts:
                print("Превышено количество подряд идущих тайм-аутов. Завершение трассировки.")
                break

            ip_str = ' '.join(ips) if ips else "*"
            print(f"{ttl:<4} {ip_str:<15} {' '.join(times)}")
            send_socket.close()

        else:
            print(f"\nЦель не достигнута за максимальное количество хопов ({max_hops}).")

    except KeyboardInterrupt:
        print("\nТрассировка прервана пользователем.")
    finally:
        recv_socket.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = input("Введите адрес назначения (например, google.com): ")
    traceroute(target_host)
