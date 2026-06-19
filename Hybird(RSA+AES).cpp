#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <string>
#include <chrono>   // 속도 측정용

// ================================================================
//  유틸: 바이트 배열 Hex 출력
// ================================================================
static void print_hex(const char* label, const unsigned char* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
    std::cout << std::dec << "\n";
}

// ================================================================
//  RSA Engine
// ================================================================
class RSA_Engine {
private:
    long long p, q, n, phi, e, d;

    long long mul_mod(long long a, long long b, long long mod) {
        long long res = 0;
        a = a % mod;
        while (b > 0) {
            if (b % 2 == 1) res = (res + a) % mod;
            a = (a + a) % mod;
            b /= 2;
        }
        return res;
    }

    long long power_mod(long long base, long long exp, long long mod) {
        long long result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) result = mul_mod(result, base, mod);
            base = mul_mod(base, base, mod);
            exp /= 2;
        }
        return result;
    }

    long long gcd(long long a, long long b) {
        while (b != 0) { long long t = b; b = a % b; a = t; }
        return a;
    }

    long long extended_gcd(long long a, long long b, long long* x, long long* y) {
        if (a == 0 || b == 0) return 0;
        long long x0 = 1, x1 = 0, y0 = 0, y1 = 1;
        while (b != 0) {
            long long q = a / b;
            long long r = a % b;       // r 먼저 저장
            long long nx = x0 - q * x1;
            long long ny = y0 - q * y1;
            a = b; b = r;               // 그 다음 갱신
            x0 = x1; x1 = nx;
            y0 = y1; y1 = ny;
        }
        *x = x0; *y = y0;
        return a;
    }

    bool is_prime(long long n) {
        if (n < 2) return false;
        for (long long i = 2; i * i <= n; i++)
            if (n % i == 0) return false;
        return true;
    }

public:
    // 키 생성: 사용자 입력
    void generate_keys() {
        std::cout << "\n[RSA 키 생성]\n";
        while (true) {
            std::cout << "소수 p 입력: "; std::cin >> p;
            std::cout << "소수 q 입력: "; std::cin >> q;
            if (!is_prime(p) || !is_prime(q)) {
                std::cout << "!! p, q 모두 소수여야 합니다. 다시 입력해 주세요.\n";
                continue;
            }
            if (p == q) {
                std::cout << "!! p와 q는 서로 달라야 합니다.\n";
                continue;
            }
            n = p * q;
            phi = (p - 1) * (q - 1);
            if (n <= 255) {
                std::cout << "!! n = p*q = " << n << " 이 255 이하입니다. 더 큰 소수를 입력해 주세요. (예: p=61, q=53)\n";
                continue;
            }
            break;
        }
        std::cout << "=> n = " << n << ", phi(n) = " << phi << "\n";

        while (true) {
            std::cout << "공개키 e 입력 (1 < e < " << phi << ", phi와 서로소): ";
            std::cin >> e;
            if (e <= 1) { std::cout << "!! e는 1보다 커야 합니다.\n"; continue; }
            if (e >= phi) { std::cout << "!! e는 phi(n)보다 작아야 합니다.\n"; continue; }
            if (gcd(phi, e) != 1) { std::cout << "!! e와 phi(n)이 서로소가 아닙니다.\n"; continue; }
            break;
        }

        long long x, y;
        long long eg = extended_gcd(phi, e, &x, &y);
        if (eg != 1) { std::cout << "!! 역원 계산 실패\n"; return; }
        d = ((y % phi) + phi) % phi;

        std::cout << "=> 공개키 (e=" << e << ", n=" << n << ")\n";
        std::cout << "=> 개인키 (d=" << d << ", n=" << n << ")\n";
    }

    // 세션키 16바이트를 1바이트씩 RSA 암호화
    // 조건: n > 255 (각 바이트 값 최대 255)
    void encrypt_aes_key(const unsigned char* aes_key,
        std::vector<long long>& enc_blocks) {
        enc_blocks.resize(32);
        for (int i = 0; i < 32; i++)
            enc_blocks[i] = power_mod((long long)aes_key[i], e, n);
    }

    void decrypt_aes_key(const std::vector<long long>& enc_blocks,
        unsigned char* aes_key_out) {
        for (int i = 0; i < 32; i++)
            aes_key_out[i] = (unsigned char)power_mod(enc_blocks[i], d, n);
    }

    long long get_n() const { return n; }
    long long get_e() const { return e; }
    long long get_d() const { return d; }
};

// ================================================================
//  AES-256 Engine
// ================================================================
class AES_Engine {
private:
    const unsigned char sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };
    const unsigned char inv_sbox[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };
    const unsigned char rcon[11] = {
        0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
    };

    unsigned char round_keys[15][16];

    void key_expansion(const unsigned char* key) {
        unsigned char w[240] = { 0 };
        for (int i = 0; i < 32; i++) w[i] = key[i];
        for (int i = 8; i < 60; i++) {
            unsigned char temp[4];
            for (int j = 0; j < 4; j++) temp[j] = w[(i - 1) * 4 + j];
            if (i % 8 == 0) {
                unsigned char t = temp[0];
                temp[0] = sbox[temp[1]] ^ rcon[i / 8];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[t];
            }
            else if (i % 8 == 4) {
                for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
            }
            for (int j = 0; j < 4; j++)
                w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
        }
        for (int r = 0; r < 15; r++)
            for (int b = 0; b < 16; b++)
                round_keys[r][b] = w[r * 16 + b];
    }

    unsigned char galois_mul(unsigned char a, unsigned char b) {
        unsigned char p = 0;
        for (int i = 0; i < 8; i++) {
            if (b & 1) p ^= a;
            unsigned char hi = a & 0x80;
            a <<= 1;
            if (hi) a ^= 0x1b;
            b >>= 1;
        }
        return p;
    }

    void sub_bytes(unsigned char s[4][4]) {
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = sbox[s[i][j]];
    }
    void inv_sub_bytes(unsigned char s[4][4]) {
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = inv_sbox[s[i][j]];
    }
    void shift_rows(unsigned char s[4][4]) {
        unsigned char t[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) t[c] = s[r][(c + r) % 4];
            for (int c = 0; c < 4; c++) s[r][c] = t[c];
        }
    }
    void inv_shift_rows(unsigned char s[4][4]) {
        unsigned char t[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) t[c] = s[r][(c - r + 4) % 4];
            for (int c = 0; c < 4; c++) s[r][c] = t[c];
        }
    }
    void mix_columns(unsigned char s[4][4]) {
        unsigned char t[4][4];
        for (int c = 0; c < 4; c++) {
            t[0][c] = galois_mul(s[0][c], 2) ^ galois_mul(s[1][c], 3) ^ s[2][c] ^ s[3][c];
            t[1][c] = s[0][c] ^ galois_mul(s[1][c], 2) ^ galois_mul(s[2][c], 3) ^ s[3][c];
            t[2][c] = s[0][c] ^ s[1][c] ^ galois_mul(s[2][c], 2) ^ galois_mul(s[3][c], 3);
            t[3][c] = galois_mul(s[0][c], 3) ^ s[1][c] ^ s[2][c] ^ galois_mul(s[3][c], 2);
        }
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = t[i][j];
    }
    void inv_mix_columns(unsigned char s[4][4]) {
        unsigned char t[4][4];
        for (int c = 0; c < 4; c++) {
            t[0][c] = galois_mul(s[0][c], 14) ^ galois_mul(s[1][c], 11) ^ galois_mul(s[2][c], 13) ^ galois_mul(s[3][c], 9);
            t[1][c] = galois_mul(s[0][c], 9) ^ galois_mul(s[1][c], 14) ^ galois_mul(s[2][c], 11) ^ galois_mul(s[3][c], 13);
            t[2][c] = galois_mul(s[0][c], 13) ^ galois_mul(s[1][c], 9) ^ galois_mul(s[2][c], 14) ^ galois_mul(s[3][c], 11);
            t[3][c] = galois_mul(s[0][c], 11) ^ galois_mul(s[1][c], 13) ^ galois_mul(s[2][c], 9) ^ galois_mul(s[3][c], 14);
        }
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] = t[i][j];
    }
    void add_round_key(unsigned char s[4][4], int round) {
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[i][j] ^= round_keys[round][j * 4 + i];
    }

    void encrypt_block(const unsigned char* in, unsigned char* out) {
        unsigned char s[4][4];
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[j][i] = in[i * 4 + j];
        add_round_key(s, 0);
        for (int r = 1; r <= 13; r++) { sub_bytes(s); shift_rows(s); mix_columns(s); add_round_key(s, r); }
        sub_bytes(s); shift_rows(s); add_round_key(s, 14);
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) out[i * 4 + j] = s[j][i];
    }
    void decrypt_block(const unsigned char* in, unsigned char* out) {
        unsigned char s[4][4];
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) s[j][i] = in[i * 4 + j];
        add_round_key(s, 14);
        for (int r = 13; r >= 1; r--) { inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, r); inv_mix_columns(s); }
        inv_shift_rows(s); inv_sub_bytes(s); add_round_key(s, 0);
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) out[i * 4 + j] = s[j][i];
    }

    void pkcs7_pad(std::vector<unsigned char>& data) {
        int pad = 16 - (data.size() % 16);
        for (int i = 0; i < pad; i++) data.push_back((unsigned char)pad);
    }
    void pkcs7_unpad(std::vector<unsigned char>& data) {
        if (data.empty()) return;
        unsigned char pad = data.back();
        if (pad == 0 || pad > 16) return;
        data.resize(data.size() - pad);
    }

public:
    void set_key(const unsigned char* key) { key_expansion(key); }

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext) {
        std::vector<unsigned char> data = plaintext;
        pkcs7_pad(data);
        std::vector<unsigned char> out(data.size());
        for (size_t i = 0; i < data.size(); i += 16)
            encrypt_block(&data[i], &out[i]);
        return out;
    }

    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext) {
        std::vector<unsigned char> out(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i += 16)
            decrypt_block(&ciphertext[i], &out[i]);
        pkcs7_unpad(out);
        return out;
    }
};

// ================================================================
//  Hybrid Crypto Engine
//  흐름:
//  [암호화] AES 세션키 생성 → RSA로 세션키 보호 → AES로 데이터 암호화
//  [복호화] RSA로 세션키 복원 → AES로 데이터 복호화
// ================================================================
class Hybrid_Engine {
private:
    RSA_Engine rsa;
    AES_Engine aes;

    // 실습용 고정 AES-256 세션키 (32바이트)
    // 실제 구현에서는 난수로 생성하며 RSA로 보호되어 전달됨
    unsigned char session_key[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
        0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
    };

    // RSA로 암호화된 세션키 블록 (바이트당 1개, 총 32개)
    std::vector<long long> enc_blocks;

public:
    void run() {
        std::cout << "========================================\n";
        std::cout << "   RSA + AES 하이브리드 암호 시스템    \n";
        std::cout << "========================================\n";

        // ── 1단계: RSA 키 생성 ──────────────────────────────
        rsa.generate_keys();

        // ── 2단계: AES 세션키를 RSA로 암호화 ────────────────
        std::cout << "\n[세션키 보호]\n";
        print_hex("원본 세션키(Hex): ", session_key, 32);

        auto t0 = std::chrono::high_resolution_clock::now();
        rsa.encrypt_aes_key(session_key, enc_blocks);
        auto t1 = std::chrono::high_resolution_clock::now();

        std::cout << "RSA 암호화된 세션키 블록: ";
        for (int i = 0; i < 32; i++)
            std::cout << enc_blocks[i] << " ";
        std::cout << "\n";
        std::cout << "RSA 세션키 암호화 시간: "
            << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()
            << " us\n";

        // ── 3단계: 평문 입력 ─────────────────────────────────
        std::cin.ignore();
        std::string input;
        std::cout << "\n[데이터 입력]\n암호화할 문자열: ";
        std::getline(std::cin, input);

        std::vector<unsigned char> plaintext(input.begin(), input.end());

        // ── 4단계: AES로 데이터 암호화 ──────────────────────
        aes.set_key(session_key);

        auto t2 = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> ciphertext = aes.encrypt(plaintext);
        auto t3 = std::chrono::high_resolution_clock::now();

        std::cout << "\n[AES 암호화 완료]\n";
        print_hex("암호문(Hex): ", ciphertext.data(), ciphertext.size());
        std::cout << "AES 암호화 시간: "
            << std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count()
            << " us\n";

        // ── 5단계: RSA로 세션키 복호화 ──────────────────────
        std::cout << "\n[세션키 복원]\n";
        unsigned char recovered_key[32] = { 0 };

        auto t4 = std::chrono::high_resolution_clock::now();
        rsa.decrypt_aes_key(enc_blocks, recovered_key);
        auto t5 = std::chrono::high_resolution_clock::now();

        print_hex("복원된 세션키(Hex): ", recovered_key, 32);
        std::cout << "RSA 세션키 복호화 시간: "
            << std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count()
            << " us\n";

        // 세션키 복원 검증
        bool key_ok = (memcmp(session_key, recovered_key, 32) == 0);
        std::cout << "세션키 복원: " << (key_ok ? "성공" : "실패") << "\n";

        // ── 6단계: AES로 데이터 복호화 ──────────────────────
        aes.set_key(recovered_key);

        auto t6 = std::chrono::high_resolution_clock::now();
        std::vector<unsigned char> decrypted = aes.decrypt(ciphertext);
        auto t7 = std::chrono::high_resolution_clock::now();

        std::string result(decrypted.begin(), decrypted.end());
        std::cout << "\n[AES 복호화 완료]\n";
        std::cout << "복호화 결과: " << result << "\n";
        std::cout << "AES 복호화 시간: "
            << std::chrono::duration_cast<std::chrono::microseconds>(t7 - t6).count()
            << " us\n";

        // ── 7단계: 최종 검증 ─────────────────────────────────
        std::cout << "\n========================================\n";
        if (input == result && key_ok) {
            std::cout << "하이브리드 암호화/복호화 성공!\n";
            std::cout << "입력값: " << input << "\n";
            std::cout << "복구값: " << result << "\n";
        }
        else {
            std::cout << "실패. 중간 과정을 확인해 주세요.\n";
        }

        // ── 속도 측정 요약 ───────────────────────────────────
        std::cout << "\n[속도 측정 요약]\n";
        std::cout << "----------------------------------------\n";
        std::cout << "RSA 세션키 암호화 : "
            << std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() << " us\n";
        std::cout << "AES 데이터 암호화 : "
            << std::chrono::duration_cast<std::chrono::microseconds>(t3 - t2).count() << " us\n";
        std::cout << "RSA 세션키 복호화 : "
            << std::chrono::duration_cast<std::chrono::microseconds>(t5 - t4).count() << " us\n";
        std::cout << "AES 데이터 복호화 : "
            << std::chrono::duration_cast<std::chrono::microseconds>(t7 - t6).count() << " us\n";
        std::cout << "========================================\n";
    }
};

int main() {
    Hybrid_Engine hybrid;
    hybrid.run();
    return 0;
}