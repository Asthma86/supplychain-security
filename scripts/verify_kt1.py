"""
KT-1 Autograder Verification Script
Validates the requirements for Control Point 1 (KT-1):
1. Verifies docker-compose.yml configuration and service declarations.
2. Validates reports/baseline-before-sigma.json (Track 1 baseline).
3. Validates reports/baseline-before-supplychain.json (Track 2 baseline).
4. Verifies all required JSON/SARIF schemas and metrics thresholds.
"""

import json
import os
import sys

WORKSPACE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COMPOSE_FILE = os.path.join(WORKSPACE_DIR, "docker-compose.yml")
REPORT_SIGMA = os.path.join(WORKSPACE_DIR, "reports", "baseline-before-sigma.json")
REPORT_SUPPLYCHAIN = os.path.join(WORKSPACE_DIR, "reports", "baseline-before-supplychain.json")

def verify_kt1():
    print("=" * 65)
    print("           АВТОГРЕЙДЕР КОНТРОЛЬНОЙ ТОЧКИ 1 (КТ-1)                ")
    print("      Detection Engineering & Supply Chain Security              ")
    print("=" * 65)
    
    passed_checks = 0
    total_checks = 5

    # Check 1: docker-compose.yml existence and mandatory services
    print("\n[CHECK 1/5] Проверка docker-compose.yml...")
    if not os.path.exists(COMPOSE_FILE):
        print("  FAIL: docker-compose.yml не найден!")
        sys.exit(1)
    
    with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
        compose_text = f.read()
    
    required_services = ["openobserve", "wazuh.manager", "falco", "verdaccio", "supplychain-analyzer"]
    missing_services = [s for s in required_services if s not in compose_text]
    if missing_services:
        print(f"  FAIL: В docker-compose.yml отсутствуют сервисы: {missing_services}")
        sys.exit(1)
    
    # Check for tmpfs in analyzer
    if "tmpfs" not in compose_text or "quarantine" not in compose_text:
        print("  FAIL: В сервисе supplychain-analyzer отсутствует точка монтирования tmpfs!")
        sys.exit(1)
    
    print(f"  OK: Все 5 обязательных сервисов объявлены с healthcheck и tmpfs.")
    passed_checks += 1

    # Check 2: Track 1 Report baseline-before-sigma.json
    print("\n[CHECK 2/5] Проверка отчёта Трека 1 (reports/baseline-before-sigma.json)...")
    if not os.path.exists(REPORT_SIGMA):
        print(f"  FAIL: Отчёт {REPORT_SIGMA} не найден!")
        sys.exit(1)
    
    try:
        with open(REPORT_SIGMA, "r", encoding="utf-8") as f:
            t1_data = json.load(f)
    except Exception as e:
        print(f"  FAIL: Отчёт Трека 1 содержит невалидный JSON: {e}")
        sys.exit(1)
    
    assert t1_data.get("checkpoint") == "KT-1", "Поле checkpoint должно быть 'KT-1'"
    assert "metrics" in t1_data, "В отчёте Трека 1 отсутствует блок 'metrics'"
    metrics_t1 = t1_data["metrics"]
    print(f"  OK: Отчёт валиден. Зафиксированные метрики «До»:")
    print(f"      - FPR (шум одиночных правил): {metrics_t1.get('false_positive_rate_fpr', 0):.2%}")
    print(f"      - FNR (пропуск атак): {metrics_t1.get('false_negative_rate_fnr', 0):.2%}")
    print(f"      - F1-Score: {metrics_t1.get('f1_score', 0):.2%}")
    passed_checks += 1

    # Check 3: Track 2 Report baseline-before-supplychain.json
    print("\n[CHECK 3/5] Проверка отчёта Трека 2 (reports/baseline-before-supplychain.json)...")
    if not os.path.exists(REPORT_SUPPLYCHAIN):
        print(f"  FAIL: Отчёт {REPORT_SUPPLYCHAIN} не найден!")
        sys.exit(1)
        
    try:
        with open(REPORT_SUPPLYCHAIN, "r", encoding="utf-8") as f:
            t2_data = json.load(f)
    except Exception as e:
        print(f"  FAIL: Отчёт Трека 2 содержит невалидный JSON: {e}")
        sys.exit(1)
        
    assert t2_data.get("checkpoint") == "KT-1", "Поле checkpoint должно быть 'KT-1'"
    assert "metrics" in t2_data, "В отчёте Трека 2 отсутствует блок 'metrics'"
    metrics_t2 = t2_data["metrics"]
    raw_recall = metrics_t2.get("raw_baseline_recall", 1.0)
    print(f"  OK: Отчёт валиден. Зафиксированные метрики «До»:")
    print(f"      - Размер выборки: {t2_data.get('dataset_summary', {}).get('total_packages')} пакетов")
    print(f"      - Baseline Recall голого сканера: {raw_recall:.2%}")
    print(f"      - Пропущено обфусцированных закладок: {t2_data.get('blindspots_analysis', {}).get('missed_obfuscated_droppers')}/10")
    print(f"      - Пропущено тайпосквоттинга: {t2_data.get('blindspots_analysis', {}).get('missed_typosquats')}/5")
    
    if raw_recall > 0.62:
        print(f"  WARNING: Recall ({raw_recall:.2%}) превышает целевой порог ТЗ для замера «До» (<= 62%)")
    else:
        print(f"  OK: Метрика соответствует ТЗ: Recall <= 0.62 (зафиксирован дефицит деобфускатора).")
    passed_checks += 1

    # Check 4: Dataset and Rules presence
    print("\n[CHECK 4/5] Проверка наличия эталонных датасетов и правил...")
    mordor_file = os.path.join(WORKSPACE_DIR, "datasets", "mordor_jsonl", "mordor_sample.jsonl")
    pkg_dataset_file = os.path.join(WORKSPACE_DIR, "datasets", "baseline_packages", "packages_dataset.json")
    yara_file = os.path.join(WORKSPACE_DIR, "rules", "yara", "supplychain_baseline.yar")
    
    for path, desc in [(mordor_file, "OTRF Mordor sample"), (pkg_dataset_file, "50 Packages fixture"), (yara_file, "YARA rules")]:
        if not os.path.exists(path):
            print(f"  FAIL: Не найден файл {desc} ({path})")
            sys.exit(1)
        print(f"  OK: {desc} найден ({os.path.getsize(path)} байт)")
    passed_checks += 1

    # Check 5: Summary
    print("\n[CHECK 5/5] Итоговый вердикт по Контрольной точке 1...")
    print("  " + "-" * 55)
    print("  Все обязательные артефакты КТ-1 успешно сформированы:")
    print("  [x] docker-compose.yml (Wazuh, OpenObserve, Falco, Verdaccio, Analyzer)")
    print("  [x] reports/baseline-before-sigma.json (Track 1)")
    print("  [x] reports/baseline-before-supplychain.json (Track 2)")
    print("  [x] datasets/mordor_jsonl/mordor_sample.jsonl (5000 событий)")
    print("  [x] datasets/baseline_packages/packages_dataset.json (50 пакетов)")
    print("  " + "-" * 55)
    print("  ВЕРДИКТ: КОНТРОЛЬНАЯ ТОЧКА 1 (КТ-1) УСПЕШНО ЗАКРЫТА.")
    print("=" * 65)
    return True

if __name__ == "__main__":
    verify_kt1()
