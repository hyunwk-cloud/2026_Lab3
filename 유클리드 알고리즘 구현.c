#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>

// 유클리드 알고리즘 구현
int gcd(int num1, int num2) {
	if (num1 == 0 || num2 == 0) {
		return 0;
	}
	int temp;

	while (num2 != 0) {
		temp = num1 % num2;
		num1 = num2;
		num2 = temp;
	}
	return num1;
}

// 확장 유클리드 알고리즘 구현
int extended_gcd(int num3, int num4, int* x, int* y) {
	if (num3 == 0 || num4 == 0) {
		return 0;
	}

	int x0 = 1, x1 = 0;
	int y0 = 0, y1 = 1;
	int q, r, next_x, next_y;

	int egcd_a = num3, egcd_b = num4;

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


int main() {
	int choice;
	int a, b, c, d, x, y, res, res2; // 변수 선언을 위로 모았어 (switch문 에러 방지)

	while (1) {
		printf("\n==============================\n");
		printf("원하는 것을 고르시오 \n");
		printf("1. 기본 유클리드 알고리즘 테스트 \n");
		printf("2. 확장형 유클리드 알고리즘 테스트 \n");
		printf("3. 1번과 2번 모두 테스트 \n");
		printf("4. 그냥 나가기 \n");
		printf("============================== \n");
		printf("선택: ");

		// 1. scanf에 & 추가 (안 하면 튕김!)
		if (scanf("%d", &choice) != 1) break;

		// 2. 종료 조건 (4번 누르면 바로 종료)
		if (choice == 4) {
			printf("프로그램을 종료합니다. \n");
			break;
		}

		// 3. 네가 짠 switch문을 while문 안으로 넣어야 메뉴가 반복돼!
		switch (choice) {

		case 1: // case(1) 대신 case 1: 이 정석이야
			printf("\n기본 유클리드 알고리즘 \n");
			printf("첫 번째 숫자를 입력해주세요: ");
			scanf("%d", &a);
			printf("두 번째 숫자를 입력해주세요: ");
			scanf("%d", &b);

			res = gcd(a, b);
			if (res == 0) {
				printf("오류!! 0은 입력할 수 없습니다. \n");
			}
			else {
				printf("첫번째 숫자인 %d 와 두번째 숫자인 %d의 최대공약수(gcd)는 %d입니다. \n", a, b, res);
			}
			break;

		case 2:
			printf("\n확장 유클리드 알고리즘 \n");
			printf("첫 번째 숫자를 입력해주세요: ");
			scanf("%d", &c);
			printf("두 번째 숫자를 입력해주세요: ");
			scanf("%d", &d);

			res2 = extended_gcd(c, d, &x, &y);
			if (res2 == 0) {
				printf("오류!! 0은 입력할 수 없습니다. \n");
			}
			else {
				printf("계수 x: %d, y: %d\n", x, y);
				printf("검증: %d*(%d) + %d*(%d) = %d\n", c, x, d, y, res2);
			}
			break;

		case 3:
			printf("\n[1, 2 모두 테스트 모드]\n");
			printf("첫 번째 숫자: "); scanf("%d", &a);
			printf("두 번째 숫자: "); scanf("%d", &b);

			res = gcd(a, b);
			if (res == 0) {
				printf("오류!! 0은 입력할 수 없습니다.\n");
			}
			else {
				printf("1. 기본 GCD 결과: %d\n", res);
				res2 = extended_gcd(a, b, &x, &y);
				printf("2. 확장 계수 결과: x = %d, y = %d\n", x, y);
				printf("   검증식: %d*(%d) + %d*(%d) = %d\n", a, x, b, y, res2);
			}
			break;

		default:
			printf("잘못된 번호입니다. 1~4 사이의 숫자를 입력해주세요.\n");
			break;
		} // switch 끝
	} // while 끝

	return 0;
}