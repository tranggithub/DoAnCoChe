import ssdeep
import pymysql
import os
import hashlib
import pefile
import pehash
import glob

CLEAN_FOLDER_PATH = "./1000_third_files/clean_files_3"
MALICIOUS_FOLDER_PATH = "./1000_third_files/infected_files_3"
IM_DB_PATH = "imph.txt"
PE_DB_PATH = "peh.txt"
SH_DB_PATH = "sdh.txt"
RSH_DB_PATH = "rsdh.txt"

CFI_IM = 0.261
CFI_PE = 0.242
CFI_SD = 0.24
CFI_RSD = 0.257

FILESCORE_FUZZYLOGIC_CLEAN_PATH = "FileScore/FuzzyLogic/FileScoreClean"
FILESCORE_FUZZYLOGIC_MALICIOUS_PATH = "FileScore/FuzzyLogic/FileScoreMalicious"
FILESCORE_COMMONFACTORMETHOD_CLEAN_PATH  ="FileScore/CommonFactorMethod/FileScoreClean"
FILESCORE_COMMONFACTORMETHOD_MALICIOUS_PATH  ="FileScore/CommonFactorMethod/FileScoreMalicious"

def calculate_md5(file_path):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            return md5_hash
    except:
        return "NULL"
    
def calculate_pehash(file_path):
    try:
        pehash_result = pehash.totalhash_hex(file_path)
        return pehash_result
    except:
        return "NULL"
    

def calculate_imphash(file_path):
    try:
        pe = pefile.PE(file_path)
        
        # Tính toán ImpHash
        imphash = pe.get_imphash()
        
        return imphash
    except pefile.PEFormatError:
        return "NULL"
    
def calculate_ssdeep_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_data = file.read()
        hash_value = ssdeep.hash(file_data)
        return hash_value
    except:
        return "NULL"
    
def calculate_resource_ssdeep_hash(file_path):
    try:
        pe = pefile.PE(file_path)

        combined_data = b""  # Dữ liệu kết hợp của tất cả các tài nguyên

        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resource_section = pe.DIRECTORY_ENTRY_RESOURCE

            for resource_type in resource_section.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    data_rva = resource_lang.data.struct.OffsetToData
                                    size = resource_lang.data.struct.Size
                                    data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                                    combined_data += data  # Gom tất cả các tài nguyên lại

        pe.close()

        ssdeep_hash = ssdeep.hash(combined_data)  # Tính toán SSDeep hash của dữ liệu kết hợp
        return ssdeep_hash
    except:
        return "NULL"


with open(FILESCORE_FUZZYLOGIC_CLEAN_PATH , "w") as file:
    file.write("")
with open(FILESCORE_FUZZYLOGIC_MALICIOUS_PATH , "w") as file:
    file.write("")
with open(FILESCORE_COMMONFACTORMETHOD_CLEAN_PATH , "w") as file:
    file.write("")
with open(FILESCORE_COMMONFACTORMETHOD_MALICIOUS_PATH , "w") as file:
    file.write("")
  
FILESCORE_FUZZYLOGIC_CLEAN = ""
FILESCORE_FUZZYLOGIC_MALICIOUS = ""
FILESCORE_COMMONFACTORMETHOD_CLEAN = ""
FILESCORE_COMMONFACTORMETHOD_MALICIOUS = ""
    
def cal_ESF_Imp_Pe (result, db_path, Matrix):
    #print(db_path)
    with open(db_path, 'r') as file:
        for line in file:
            processed_line = line.rstrip()  # Loại bỏ ký tự xuống dòng
            #print(processed_line)
            if (result == processed_line):
                if (db_path == IM_DB_PATH):
                    Matrix[0] = CFI_IM
                else:
                    Matrix[1] = CFI_PE

def calculate_max_similar (result, db_path):
    max = 0
    with open(db_path, 'r') as file:
        for line in file:
            processed_line = line.rstrip()  # Loại bỏ ký tự xuống dòng
            similar = ssdeep.compare(processed_line, result)
            if (similar > max):
                max = similar
    return max/100
            
def cal_ESF_Sd_RSd (result, db_path, Matrix):
    #print(db_path)
    max_similar = calculate_max_similar (result, db_path)
    if (db_path == SH_DB_PATH):
        Matrix[2] = CFI_SD * max_similar
    else:
        Matrix[3] = CFI_RSD * max_similar
        
def FuzzyLogic (a, b):
    return a + b - a * b
def TheCertaintyFactorModel (a, b):
    return (a + b)/(1 + a * b)
def getCombineMethodFuzzyLogic(ESF):
    result = FuzzyLogic(ESF[0], ESF[1])
    result = FuzzyLogic(result, ESF[2])
    return FuzzyLogic(result, ESF[3])
    
def getCombineMethodTheCertaintyFactorModel(ESF):
    result = TheCertaintyFactorModel(ESF[0], ESF[1])
    result = TheCertaintyFactorModel(result, ESF[2])
    return TheCertaintyFactorModel(result, ESF[3])

def insert_score_to_database(filename, score, flag):
    conn = pymysql.connect(
        host='10.0.139.42',
        user='pengu',
        password='123456',
        database='dataset'
    )
    cursor = conn.cursor()
    if flag == "flm":
        query = "INSERT INTO flm_results (file, score) VALUES (%s, %s) ON DUPLICATE KEY UPDATE score = %s"
    else:
        query = "INSERT INTO cfm_results (file, score) VALUES (%s, %s) ON DUPLICATE KEY UPDATE score = %s"
    values = (filename, score, score)
    cursor.execute(query, values)
    
    conn.commit()
    
    cursor.close()
    conn.close()


def CombinationApproach(files, lable):
    global FILESCORE_FUZZYLOGIC_CLEAN, FILESCORE_COMMONFACTORMETHOD_CLEAN, FILESCORE_FUZZYLOGIC_MALICIOUS, FILESCORE_COMMONFACTORMETHOD_MALICIOUS
    
    # Duyệt qua từng tệp tin trong danh sách
    for file_path in files:
        #Gọi ra từng tập tin trong dataset 3
        if os.path.isfile(file_path):  # Kiểm tra nếu là tệp tin
            # Khởi tạo ESF ban đầu cho từng loại hash là 0; [Imp, Pe, Sd, RSd] 
            ESF = [0, 0, 0, 0]
            filename = os.path.basename(file_path)
            #print(file_path)
            # Thực hiện các thao tác với tệp tin
            md5_result = calculate_md5(file_path)
            imp_result =  calculate_imphash(file_path)
            peh_result = calculate_pehash(file_path)
            sd_result = calculate_ssdeep_hash(file_path)
            rsd_result = calculate_resource_ssdeep_hash(file_path)

            #print(imp_result)
            cal_ESF_Imp_Pe(imp_result,IM_DB_PATH,ESF)
            cal_ESF_Imp_Pe(peh_result,PE_DB_PATH,ESF)
            cal_ESF_Sd_RSd(sd_result,SH_DB_PATH,ESF)
            cal_ESF_Sd_RSd(rsd_result,RSH_DB_PATH,ESF)
            #print(ESF)
            ESF_FuzzyLogic = getCombineMethodFuzzyLogic(ESF) * 100
            #insert_score_to_database(filename, "{:.1f}".format(ESF_FuzzyLogic), "flm")

            ESF_TheCertaintyFactorModel = getCombineMethodTheCertaintyFactorModel(ESF) * 100
            #insert_score_to_database(filename, "{:.1f}".format(ESF_TheCertaintyFactorModel), "cfm")

            if (lable == "clean"):
                FILESCORE_FUZZYLOGIC_CLEAN = FILESCORE_FUZZYLOGIC_CLEAN + "{:.1f}".format(ESF_FuzzyLogic) + "\n"
                FILESCORE_COMMONFACTORMETHOD_CLEAN = FILESCORE_COMMONFACTORMETHOD_CLEAN + ("{:.1f}".format(ESF_TheCertaintyFactorModel) + "\n")
            else:
                FILESCORE_FUZZYLOGIC_MALICIOUS = FILESCORE_FUZZYLOGIC_MALICIOUS + ("{:.1f}".format(ESF_FuzzyLogic) + "\n")
                FILESCORE_COMMONFACTORMETHOD_MALICIOUS = FILESCORE_COMMONFACTORMETHOD_MALICIOUS + ("{:.1f}".format(ESF_TheCertaintyFactorModel) + "\n")
            
            print("Insert score for", filename)
            


# Sử dụng pattern "*" để lấy danh sách tất cả các tệp tin trong thư mục
files = glob.glob(CLEAN_FOLDER_PATH + "/*")
CombinationApproach(files, "clean")    

files = glob.glob(MALICIOUS_FOLDER_PATH + "/*")
CombinationApproach(files, "malicious")

with open(FILESCORE_FUZZYLOGIC_CLEAN_PATH , "w") as file:
    file.write(FILESCORE_FUZZYLOGIC_CLEAN)
with open(FILESCORE_FUZZYLOGIC_MALICIOUS_PATH , "w") as file:
    file.write(FILESCORE_FUZZYLOGIC_MALICIOUS)
with open(FILESCORE_COMMONFACTORMETHOD_CLEAN_PATH , "w") as file:
    file.write(FILESCORE_COMMONFACTORMETHOD_CLEAN)
with open(FILESCORE_COMMONFACTORMETHOD_MALICIOUS_PATH , "w") as file:
    file.write(FILESCORE_COMMONFACTORMETHOD_MALICIOUS)
