from log_analyzer import analyze_brute_force

def test_empty_logs_handling():
    # 1. إرسال قائمة فارغة تماماً
    empty_data = []
    
    # 2. تشغيل الدالة
    result = analyze_brute_force(empty_data)
    assert len(result) == 0
