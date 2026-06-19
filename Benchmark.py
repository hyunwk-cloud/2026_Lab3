import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
import os

# 한글 폰트 설정 (Windows 기준)
matplotlib.rcParams['font.family'] = 'Malgun Gothic'
matplotlib.rcParams['axes.unicode_minus'] = False

# ── CSV 로드 ──────────────────────────────────────────────────────
CSV_FILE = "benchmark_result.csv"

if not os.path.exists(CSV_FILE):
    print(f"[오류] {CSV_FILE} 파일이 없습니다.")
    print("C++ 프로그램에서 메뉴 2번(성능 벤치마크)을 먼저 실행해 주세요.")
    exit(1)

df = pd.read_csv(CSV_FILE)
print("=== 로드된 데이터 ===")
print(df.to_string(index=False))
print()

labels    = df["label"]
sizes     = df["size_byte"]
aes_enc   = df["aes_enc_us"]
aes_dec   = df["aes_dec_us"]
rsa_enc   = df["rsa_key_enc_us"]
rsa_dec   = df["rsa_key_dec_us"]
hybrid    = df["hybrid_total_us"]

OUTPUT_DIR = "graphs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── 그래프 1: AES 암복호화 시간 비교 (막대) ──────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
x = range(len(labels))
width = 0.35
ax.bar([i - width/2 for i in x], aes_enc, width, label="AES 암호화", color="#4C72B0")
ax.bar([i + width/2 for i in x], aes_dec, width, label="AES 복호화", color="#DD8452")
ax.set_xticks(list(x))
ax.set_xticklabels(labels)
ax.set_xlabel("데이터 크기")
ax.set_ylabel("처리 시간 (μs)")
ax.set_title("AES-256 암복호화 시간 비교 (100회 평균)")
ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
path1 = os.path.join(OUTPUT_DIR, "01_aes_enc_dec.png")
plt.savefig(path1, dpi=150)
plt.close()
print(f"저장: {path1}")

# ── 그래프 2: RSA 세션키 암복호화 시간 (막대) ────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar([i - width/2 for i in x], rsa_enc, width, label="RSA 키 암호화", color="#55A868")
ax.bar([i + width/2 for i in x], rsa_dec, width, label="RSA 키 복호화", color="#C44E52")
ax.set_xticks(list(x))
ax.set_xticklabels(labels)
ax.set_xlabel("데이터 크기 (RSA는 키 크기 고정)")
ax.set_ylabel("처리 시간 (μs)")
ax.set_title("RSA 세션키 암복호화 시간 (100회 평균)")
ax.legend()
ax.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
path2 = os.path.join(OUTPUT_DIR, "02_rsa_key_enc_dec.png")
plt.savefig(path2, dpi=150)
plt.close()
print(f"저장: {path2}")

# ── 그래프 3: AES vs 하이브리드 전체 비교 (선 그래프) ────────────
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(labels, aes_enc, marker="o", label="AES 암호화만", color="#4C72B0", linewidth=2)
ax.plot(labels, hybrid,  marker="s", label="하이브리드 합계", color="#C44E52", linewidth=2, linestyle="--")
ax.set_xlabel("데이터 크기")
ax.set_ylabel("처리 시간 (μs)")
ax.set_title("AES 단독 vs 하이브리드 암호화 시간 비교")
ax.legend()
ax.grid(linestyle="--", alpha=0.5)
plt.tight_layout()
path3 = os.path.join(OUTPUT_DIR, "03_aes_vs_hybrid.png")
plt.savefig(path3, dpi=150)
plt.close()
print(f"저장: {path3}")

# ── 그래프 4: 하이브리드 구성 요소 스택 막대 ─────────────────────
fig, ax = plt.subplots(figsize=(10, 5))
ax.bar(labels, rsa_enc, label="RSA 키 암호화", color="#55A868")
ax.bar(labels, aes_enc, bottom=rsa_enc, label="AES 데이터 암호화", color="#4C72B0")
ax.bar(labels, rsa_dec, bottom=rsa_enc + aes_enc, label="RSA 키 복호화", color="#C44E52")
ax.bar(labels, aes_dec, bottom=rsa_enc + aes_enc + rsa_dec, label="AES 데이터 복호화", color="#DD8452")
ax.set_xlabel("데이터 크기")
ax.set_ylabel("처리 시간 (μs)")
ax.set_title("하이브리드 암호화 구성 요소별 시간 분포")
ax.legend(loc="upper left")
ax.grid(axis="y", linestyle="--", alpha=0.5)
plt.tight_layout()
path4 = os.path.join(OUTPUT_DIR, "04_hybrid_breakdown.png")
plt.savefig(path4, dpi=150)
plt.close()
print(f"저장: {path4}")

# ── 그래프 5: 데이터 크기 vs AES 처리 시간 (선형성 확인) ─────────
fig, ax = plt.subplots(figsize=(10, 5))
ax.plot(sizes, aes_enc, marker="o", color="#4C72B0", linewidth=2, label="AES 암호화")
ax.plot(sizes, aes_dec, marker="^", color="#DD8452", linewidth=2, label="AES 복호화")
ax.set_xlabel("데이터 크기 (byte)")
ax.set_ylabel("처리 시간 (μs)")
ax.set_title("데이터 크기에 따른 AES 처리 시간 선형성 확인")
ax.legend()
ax.grid(linestyle="--", alpha=0.5)
plt.tight_layout()
path5 = os.path.join(OUTPUT_DIR, "05_aes_linearity.png")
plt.savefig(path5, dpi=150)
plt.close()
print(f"저장: {path5}")

print("\n모든 그래프가 graphs/ 폴더에 저장되었습니다.")
print("보고서에 사용할 그림 파일:")
for p in [path1, path2, path3, path4, path5]:
    print(f"  {p}")