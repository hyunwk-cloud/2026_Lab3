#define _CRT_SECURE_NO_WARNINGS
#include <iostream>

// long long 범위에서 오버플로우 없이 곱한 후 모듈로 연산하는 안전한 함수
long long mul_mod(long long a, long long b, long long mod) {
    long long res = 0;
    a = a % mod;
    while (b > 0) {
        if (b % 2 == 1) {
            res = (res + a) % mod;
        }
        a = (a + a) % mod;  // a가 이미 a % mod 상태이므로
                            // a < mod 보장되면 a+a는 최대 2*(mod-1)
                            // long long 범위에서 mod < 2^62이면 안전
        b /= 2;
    }
    return res;
}

// 거듭제곱 나머지 연산
long long power_mod(long long base, long long exp, long long mod) {
    long long pomd_res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) {
            pomd_res = mul_mod(pomd_res, base, mod);
        }
        base = mul_mod(base, base, mod);
        exp /= 2;
    }
    return pomd_res;
}

// 유클리드 알고리즘
long long gcd(long long num1, long long num2) {
    if (num1 == 0 || num2 == 0) return 0;
    long long temp;
    while (num2 != 0) {
        temp = num1 % num2;
        num1 = num2;
        num2 = temp;
    }
    return num1;
}

// 확장 유클리드 알고리즘
long long extended_gcd(long long num3, long long num4, long long* x, long long* y) {
    if (num3 == 0 || num4 == 0) return 0;

    long long x0 = 1, x1 = 0;
    long long y0 = 0, y1 = 1;
    long long q, r, next_x, next_y;
    long long egcd_a = num3, egcd_b = num4;

    while (egcd_b != 0) {
        q = egcd_a / egcd_b;
        r = egcd_a % egcd_b;

        next_x = x0 - q * x1;
        next_y = y0 - q * y1;

        egcd_a = egcd_b;
        egcd_b = r;

        x0 = x1;
        x1 = next_x;

        y0 = y1;
        y1 = next_y;
    }

    *x = x0;
    *y = y0;

    return egcd_a;
}

// 소수 검증 함수
bool is_prime(long long n) {
    if (n < 2) return false;
    for (long long i = 2; i * i <= n; i++) {
        if (n % i == 0) return false;
    }
    return true;
}

// RSA 암호화 엔진 클래스
class RSA_Engine {
private:
    long long p, q, n, phi, e, d;

public:
    void run_RSA() {
        std::cout << " RSA 암호화\n";
        std::cout << "======================================\n\n";

        // 1. 키 생성
        std::cout << "[1단계: 키 생성]\n";
        while (true) {
            std::cout << "첫 번째 소수 p: ";
            std::cin >> p;
            std::cout << "두 번째 소수 q: ";
            std::cin >> q;

            if (!is_prime(p) || !is_prime(q)) {
                std::cout << "!! 오류: p 또는 q가 소수가 아님. 다시 입력 바람.\n\n";
                continue;
            }
            break;
        }

        n = p * q;
        phi = (p - 1) * (q - 1);
        std::cout << "=> n = " << n << ", phi(n) = " << phi << "\n";

        // e 입력 루프 + 조건별 분리 메시지 (개선 4번)
        while (true) {
            std::cout << "공개키 e 입력 (1 < e < " << phi << ", phi와 서로소): ";
            std::cin >> e;

            if (e <= 1) {
                std::cout << "!! e는 1보다 커야 합니다.\n";
                continue;
            }
            if (e >= phi) {
                std::cout << "!! e는 phi(n)=" << phi << "보다 작아야 합니다.\n";
                continue;
            }
            if (gcd(phi, e) != 1) {
                std::cout << "!! e와 phi(n)=" << phi << "가 서로소가 아닙니다.\n";
                continue;
            }
            break;
        }

        // 개인키 d 산출 + 반환값 검증 (개선 3번)
        long long x, y;
        long long egcd_result = extended_gcd(phi, e, &x, &y);
        if (egcd_result != 1) {
            std::cout << "!! 내부 오류: 역원 계산 실패 (gcd = " << egcd_result << ")\n";
            return;
        }
        d = ((y % phi) + phi) % phi;
        std::cout << "=> 생성된 개인키 d = " << d << "\n\n";

        // 2. 암호화
        long long M, C, decryptedM;

        std::cout << "[2단계: 암호화]\n";
        std::cout << "암호화할 숫자(평문) M 입력 (n보다 작게): ";
        std::cin >> M;

        if (M >= n) {
            std::cout << "!! 경고: M이 n보다 크면 올바르게 복호화되지 않음.\n";
        }

        C = power_mod(M, e, n);
        std::cout << "=> 암호화 완료! 암호문 C = " << C << "\n\n";

        // 3. 복호화
        std::cout << "[3단계: 복호화]\n";
        std::cout << "개인키 d를 사용하여 복호화를 진행...\n";

        decryptedM = power_mod(C, d, n);
        std::cout << "=> 복호화 완료! 결과 숫자 M = " << decryptedM << "\n\n";

        // 4. 검증
        std::cout << "======================================\n";
        if (M == decryptedM) {
            std::cout << "RSA 복호화 성공!\n";
            std::cout << "입력값 " << M << " == 복구값 " << decryptedM << "\n";
        }
        else {
            std::cout << "복호화 실패... 계산 과정을 다시 확인바람.\n";
        }
        std::cout << "======================================\n";
    }
};

int main() {
    RSA_Engine rsa;
    rsa.run_RSA();
    return 0;
}