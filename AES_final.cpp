#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <string>

class AES_Engine {
private:
    // S-Box (암호화용)
    const unsigned char sbox[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    // 역 S-Box (복호화용)
    const unsigned char inv_sbox[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    // Rcon 상수 (AES-256은 rcon[1]~rcon[7]까지 사용)
    const unsigned char rcon[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    // AES-256: 15개 라운드 키 × 16바이트 = 240바이트
    unsigned char round_keys[15][16];

    // ===================== 키 확장 =====================
    // flat 배열(w[240])로 워드 단위 관리 후 round_keys에 복사
    // 이전 코드의 round_keys[0] 덮어쓰기 버그 및 음수 인덱스 버그 수정
    void key_expansion(const unsigned char* key) {
        unsigned char w[240] = { 0 };

        // 초기 키 32바이트를 w[0]~w[31]에 복사
        for (int i = 0; i < 32; i++) w[i] = key[i];

        // 워드 인덱스 8부터 시작 (32바이트 = 8워드)
        for (int i = 8; i < 60; i++) {
            unsigned char temp[4];
            // 이전 워드 복사
            for (int j = 0; j < 4; j++) temp[j] = w[(i - 1) * 4 + j];

            if (i % 8 == 0) {
                // RotWord + SubWord + Rcon
                unsigned char t = temp[0];
                temp[0] = sbox[temp[1]] ^ rcon[i / 8];
                temp[1] = sbox[temp[2]];
                temp[2] = sbox[temp[3]];
                temp[3] = sbox[t];
            }
            else if (i % 8 == 4) {
                // AES-256 추가 규칙: SubWord만 적용
                for (int j = 0; j < 4; j++) temp[j] = sbox[temp[j]];
            }

            // w[i-8] XOR temp → w[i]
            for (int j = 0; j < 4; j++)
                w[i * 4 + j] = w[(i - 8) * 4 + j] ^ temp[j];
        }

        // round_keys에 복사
        for (int r = 0; r < 15; r++)
            for (int b = 0; b < 16; b++)
                round_keys[r][b] = w[r * 16 + b];
    }

    // ===================== GF(2^8) 곱셈 =====================
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

    // ===================== 암호화 라운드 함수 =====================
    void sub_bytes(unsigned char state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = sbox[state[i][j]];
    }

    void shift_rows(unsigned char state[4][4]) {
        unsigned char temp[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) temp[c] = state[r][(c + r) % 4];
            for (int c = 0; c < 4; c++) state[r][c] = temp[c];
        }
    }

    void mix_columns(unsigned char state[4][4]) {
        unsigned char tmp[4][4];
        for (int c = 0; c < 4; c++) {
            tmp[0][c] = galois_mul(state[0][c], 2) ^ galois_mul(state[1][c], 3) ^ state[2][c] ^ state[3][c];
            tmp[1][c] = state[0][c] ^ galois_mul(state[1][c], 2) ^ galois_mul(state[2][c], 3) ^ state[3][c];
            tmp[2][c] = state[0][c] ^ state[1][c] ^ galois_mul(state[2][c], 2) ^ galois_mul(state[3][c], 3);
            tmp[3][c] = galois_mul(state[0][c], 3) ^ state[1][c] ^ state[2][c] ^ galois_mul(state[3][c], 2);
        }
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = tmp[i][j];
    }

    void add_round_key(unsigned char state[4][4], int round) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] ^= round_keys[round][j * 4 + i];
    }

    // ===================== 복호화 라운드 함수 =====================
    void inv_sub_bytes(unsigned char state[4][4]) {
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = inv_sbox[state[i][j]];
    }

    // ShiftRows 역함수: 각 행을 오른쪽으로 r칸 이동
    void inv_shift_rows(unsigned char state[4][4]) {
        unsigned char temp[4];
        for (int r = 1; r < 4; r++) {
            for (int c = 0; c < 4; c++) temp[c] = state[r][(c - r + 4) % 4];
            for (int c = 0; c < 4; c++) state[r][c] = temp[c];
        }
    }

    // MixColumns 역함수: 계수 {14, 11, 13, 9} 사용
    void inv_mix_columns(unsigned char state[4][4]) {
        unsigned char tmp[4][4];
        for (int c = 0; c < 4; c++) {
            tmp[0][c] = galois_mul(state[0][c], 14) ^ galois_mul(state[1][c], 11) ^ galois_mul(state[2][c], 13) ^ galois_mul(state[3][c], 9);
            tmp[1][c] = galois_mul(state[0][c], 9) ^ galois_mul(state[1][c], 14) ^ galois_mul(state[2][c], 11) ^ galois_mul(state[3][c], 13);
            tmp[2][c] = galois_mul(state[0][c], 13) ^ galois_mul(state[1][c], 9) ^ galois_mul(state[2][c], 14) ^ galois_mul(state[3][c], 11);
            tmp[3][c] = galois_mul(state[0][c], 11) ^ galois_mul(state[1][c], 13) ^ galois_mul(state[2][c], 9) ^ galois_mul(state[3][c], 14);
        }
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[i][j] = tmp[i][j];
    }

    // ===================== 단일 블록 암복호화 =====================
    void encrypt_block(const unsigned char* in, unsigned char* out) {
        unsigned char state[4][4];
        // 열 우선(column-major)으로 state 채우기
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[j][i] = in[i * 4 + j];

        add_round_key(state, 0);

        for (int round = 1; round <= 13; round++) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, round);
        }
        // 마지막 라운드: MixColumns 없음
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, 14);

        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                out[i * 4 + j] = state[j][i];
    }

    void decrypt_block(const unsigned char* in, unsigned char* out) {
        unsigned char state[4][4];
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                state[j][i] = in[i * 4 + j];

        add_round_key(state, 14);

        for (int round = 13; round >= 1; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, round);
            inv_mix_columns(state);
        }
        // 마지막 역라운드: InvMixColumns 없음
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, 0);

        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                out[i * 4 + j] = state[j][i];
    }

    // ===================== PKCS#7 패딩 =====================
    // 마지막 블록이 16바이트 미만이면 부족한 바이트 수 값으로 채움
    // 예: 14바이트 → 0x02 0x02 추가
    // 정확히 16바이트여도 16바이트짜리 패딩 블록을 추가 (복호화 시 구분 위해)
    void pkcs7_pad(std::vector<unsigned char>& data) {
        int pad = 16 - (data.size() % 16);
        for (int i = 0; i < pad; i++) data.push_back((unsigned char)pad);
    }

    void pkcs7_unpad(std::vector<unsigned char>& data) {
        if (data.empty()) return;
        unsigned char pad = data.back();
        if (pad == 0 || pad > 16) return;  // 잘못된 패딩이면 무시
        data.resize(data.size() - pad);
    }

public:
    // ===================== 문자열 암호화 =====================
    void encrypt_string(const std::string& input, const unsigned char* key) {
        key_expansion(key);

        // 문자열을 바이트 벡터로 변환 후 패딩
        std::vector<unsigned char> data(input.begin(), input.end());
        pkcs7_pad(data);

        std::vector<unsigned char> encrypted(data.size());
        for (size_t i = 0; i < data.size(); i += 16)
            encrypt_block(&data[i], &encrypted[i]);

        std::cout << "\n======================================\n";
        std::cout << "       AES-256 문자열 암호화 완료      \n";
        std::cout << "======================================\n";
        std::cout << "입력 문자열 : " << input << "\n";
        std::cout << "암호문(Hex) : ";
        for (auto b : encrypted)
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        std::cout << std::dec << "\n======================================\n";
    }

    // ===================== 파일 암호화 =====================
    bool encrypt_file(const std::string& input_path, const std::string& output_path, const unsigned char* key) {
        std::ifstream fin(input_path, std::ios::binary);
        if (!fin) {
            std::cout << "!! 오류: 입력 파일을 열 수 없습니다: " << input_path << "\n";
            return false;
        }

        std::vector<unsigned char> data(
            std::istreambuf_iterator<char>(fin), {}
        );
        fin.close();

        key_expansion(key);
        pkcs7_pad(data);

        std::vector<unsigned char> encrypted(data.size());
        for (size_t i = 0; i < data.size(); i += 16)
            encrypt_block(&data[i], &encrypted[i]);

        std::ofstream fout(output_path, std::ios::binary);
        if (!fout) {
            std::cout << "!! 오류: 출력 파일을 열 수 없습니다: " << output_path << "\n";
            return false;
        }
        fout.write(reinterpret_cast<char*>(encrypted.data()), encrypted.size());
        fout.close();

        std::cout << "\n======================================\n";
        std::cout << "        AES-256 파일 암호화 완료       \n";
        std::cout << "======================================\n";
        std::cout << "입력 파일  : " << input_path << "\n";
        std::cout << "출력 파일  : " << output_path << "\n";
        std::cout << "원본 크기  : " << (data.size() - (data.back())) << " bytes\n";
        std::cout << "암호화 크기: " << encrypted.size() << " bytes\n";
        std::cout << "======================================\n";
        return true;
    }

    // ===================== 파일 복호화 =====================
    bool decrypt_file(const std::string& input_path, const std::string& output_path, const unsigned char* key) {
        std::ifstream fin(input_path, std::ios::binary);
        if (!fin) {
            std::cout << "!! 오류: 입력 파일을 열 수 없습니다: " << input_path << "\n";
            return false;
        }

        std::vector<unsigned char> data(
            std::istreambuf_iterator<char>(fin), {}
        );
        fin.close();

        if (data.size() % 16 != 0) {
            std::cout << "!! 오류: 암호문 크기가 16바이트 배수가 아닙니다. 손상된 파일일 수 있습니다.\n";
            return false;
        }

        key_expansion(key);

        std::vector<unsigned char> decrypted(data.size());
        for (size_t i = 0; i < data.size(); i += 16)
            decrypt_block(&data[i], &decrypted[i]);

        pkcs7_unpad(decrypted);

        std::ofstream fout(output_path, std::ios::binary);
        if (!fout) {
            std::cout << "!! 오류: 출력 파일을 열 수 없습니다: " << output_path << "\n";
            return false;
        }
        fout.write(reinterpret_cast<char*>(decrypted.data()), decrypted.size());
        fout.close();

        std::cout << "\n======================================\n";
        std::cout << "        AES-256 파일 복호화 완료       \n";
        std::cout << "======================================\n";
        std::cout << "입력 파일  : " << input_path << "\n";
        std::cout << "출력 파일  : " << output_path << "\n";
        std::cout << "복호화 크기: " << decrypted.size() << " bytes\n";
        std::cout << "======================================\n";
        return true;
    }
};

// ===================== main =====================
int main() {
    AES_Engine aes;

    // AES-256용 32바이트 키 (하이브리드 연동 시 RSA로 보호될 세션키)
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    int choice;
    std::cout << "======================================\n";
    std::cout << "         AES-256 암호화 엔진          \n";
    std::cout << "======================================\n";
    std::cout << "1. 문자열 암호화\n";
    std::cout << "2. 파일 암호화\n";
    std::cout << "3. 파일 복호화\n";
    std::cout << "선택: ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 1) {
        std::string input;
        std::cout << "암호화할 문자열 입력: ";
        std::getline(std::cin, input);
        aes.encrypt_string(input, key);
    }
    else if (choice == 2) {
        std::string in_path, out_path;
        std::cout << "입력 파일 경로 (예: input.txt): ";
        std::getline(std::cin, in_path);
        std::cout << "출력 파일 경로 (예: output.aes): ";
        std::getline(std::cin, out_path);
        aes.encrypt_file(in_path, out_path, key);
    }
    else if (choice == 3) {
        std::string in_path, out_path;
        std::cout << "입력 파일 경로 (예: output.aes): ";
        std::getline(std::cin, in_path);
        std::cout << "출력 파일 경로 (예: decrypted.txt): ";
        std::getline(std::cin, out_path);
        aes.decrypt_file(in_path, out_path, key);
    }
    else {
        std::cout << "!! 잘못된 선택입니다.\n";
    }

    return 0;
}