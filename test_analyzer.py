from log_analyzer import analyze_brute_force

def test_empty_logs_handling():
    # Sending a custom list
    empty_data = []
    
    # 2 run the func
    result = analyze_brute_force(empty_data)
    assert len(result) == 0
