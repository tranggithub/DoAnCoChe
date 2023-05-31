def read_scores_from_file(file_path):
    with open(file_path, 'r') as file:
        scores = file.readlines()
        scores = [float(score.strip()) for score in scores]
    return scores

def calculate_tp_fp_tn_fn(clean_scores, malicious_scores, threshold):
    tp = sum(score >= threshold for score in malicious_scores)
    fp = sum(score >= threshold for score in clean_scores)
    tn = sum(score < threshold for score in clean_scores)
    fn = sum(score < threshold for score in malicious_scores)
    
    try:
            precision = 100*tp / (tp + fp)
    except ZeroDivisionError:
        precision = "?"

    try:
        recall = 100*tp / (tp + fn)
    except ZeroDivisionError:
        recall = "?"

    try:
        accuracy = 100*(tp + tn) / (tp + fp + tn + fn)
    except ZeroDivisionError:
        accuracy = "?"

    try:
        f1_score = 2 * (precision * recall) / (precision + recall)
    except Exception:
        f1_score = "?"
    
    print("Precision:", precision)
    print("Recall:", recall)
    print("Accurancy:", accuracy)
    print("F-score:", f1_score)


clean_file_path_1 = '/home/kali/Desktop/FileScore/FuzzyLogic/FileScoreClean'  
malicious_file_path_1 = '/home/kali/Desktop/FileScore/FuzzyLogic/FileScoreMalicious'  

clean_file_path_2 = '/home/kali/Desktop/FileScore/CommonFactorMethod/FileScoreClean'  
malicious_file_path_2 = '/home/kali/Desktop/FileScore/CommonFactorMethod/FileScoreMalicious'  

GTP = 35  # Ngưỡng 1 để phân loại TP/FP/TN/FN
ATP = 65  # Ngưỡng 2 để phân loại TP/FP/TN/FN

clean_scores_1 = read_scores_from_file(clean_file_path_1)
malicious_scores_1 = read_scores_from_file(malicious_file_path_1)

clean_scores_2 = read_scores_from_file(clean_file_path_2)
malicious_scores_2 = read_scores_from_file(malicious_file_path_2)


print("\t--FUZZY LOGIC METHOD--")
print("FLM_GTP (>=35%):")
calculate_tp_fp_tn_fn(clean_scores_1, malicious_scores_1, GTP)

print("\nFLM_ATP (>=65%):")
calculate_tp_fp_tn_fn(clean_scores_1, malicious_scores_1, ATP)

print("\n\t--COMMON FACTOR METHOD--")
print("CFM_GTP (>=35%):")
calculate_tp_fp_tn_fn(clean_scores_2, malicious_scores_2, GTP)

print("\nCFM_ATP (>=65%):")
calculate_tp_fp_tn_fn(clean_scores_2, malicious_scores_2, ATP)


