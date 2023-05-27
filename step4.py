import ssdeep
import pymysql
import os
import hashlib
import pefile
import pehash
import glob

CLEAN_FOLDER_PATH = "./1000_second_files/clean_files_2"
MALICIOUS_FOLDER_PATH = "./1000_second_files/infected_files_2"
IM_DB_PATH = "imph.txt"
PE_DB_PATH = "peh.txt"
SH_DB_PATH = "sdh.txt"
RSH_DB_PATH = "rsdh.txt"
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

def set_HFlag_Imp_Pe (result, db_path, Matrix, lable):
    #print(db_path)
    with open(db_path, 'r') as file:
        for line in file:
            processed_line = line.rstrip()  # Loại bỏ ký tự xuống dòng
            #print(processed_line)
            if (result == processed_line):
                if (lable == "malicious"):
                    #TP
            	    Matrix[0] += 1
                else:
                    #FP
            	    Matrix[1] += 1
                return
        if (lable == "clean"):
            #TN
            Matrix[3] += 1
        else:
            #FN
            Matrix[2] += 1
            
def set_HFlag_Sd_RSd (result, db_path, Matrix, lable):
    #print(db_path)
    with open(db_path, 'r') as file:
        for line in file:
            processed_line = line.rstrip()  # Loại bỏ ký tự xuống dòng
            #print(processed_line)
            if (ssdeep.compare(processed_line, result) > 0):
                if (lable == "malicious"):
                    #TP
            	    Matrix[0] += 1
                else:
                    #FP
            	    Matrix[1] += 1
                return
        if (lable == "clean"):
            #TN
            Matrix[3] += 1
        else:
            #FN
            Matrix[2] += 1
# Định nghĩa Confusion Matrix [TP, FP, FN, TN])
Imp_H = [0, 0, 0, 0]
Pe_H = [0, 0, 0, 0]
Sd_H = [0, 0, 0, 0]
RSd_H = [0, 0, 0, 0]

#ssdeep.compare
def updateDetectionRate(files, lable):
    # Duyệt qua từng tệp tin trong danh sách
    for file_path in files:
        #Gọi ra từng tập tin trong dataset 2
        if os.path.isfile(file_path):  # Kiểm tra nếu là tệp tin
            HFlag_set = [4]
            #print(file_path)
            # Thực hiện các thao tác với tệp tin
            md5_result = calculate_md5(file_path)
            imp_result =  calculate_imphash(file_path)
            peh_result = calculate_pehash(file_path)
            sd_result = calculate_ssdeep_hash(file_path)
            rsd_result = calculate_resource_ssdeep_hash(file_path)

            #print(imp_result)
            set_HFlag_Imp_Pe(imp_result,IM_DB_PATH,Imp_H,lable)
            set_HFlag_Imp_Pe(peh_result,PE_DB_PATH,Pe_H,lable)
            set_HFlag_Sd_RSd(sd_result,SH_DB_PATH,Sd_H,lable)
            set_HFlag_Sd_RSd(rsd_result,RSH_DB_PATH,RSd_H,lable)
# Sử dụng pattern "*" để lấy danh sách tất cả các tệp tin trong thư mục
files = glob.glob(CLEAN_FOLDER_PATH + "/*")
updateDetectionRate(files, "clean")    

files = glob.glob(MALICIOUS_FOLDER_PATH + "/*")
updateDetectionRate(files, "malicious")

print("Detection Rate: [TP, FP, FN, TN]")
print("Imp_H", Imp_H)
print("Pe_H", Pe_H)
print("Sd_H", Sd_H)
print("RSd_H", RSd_H)
print ("\n")
        
def TDR (TP, TN, Total_Sample):
    return (TP + TN) / Total_Sample

TOTAL_SAMPLE = 1000
TDR_Imp = TDR(Imp_H[0],Imp_H[3], TOTAL_SAMPLE)
TDR_Pe = TDR(Pe_H[0],Pe_H[3], TOTAL_SAMPLE)    
TDR_Sd = TDR(Sd_H[0],Sd_H[3], TOTAL_SAMPLE)
TDR_RSd = TDR(RSd_H[0],RSd_H[3], TOTAL_SAMPLE)

print("True Detection Rate:")
print("Imp_H", TDR_Imp)
print("Pe_H", TDR_Pe)
print("Sd_H", TDR_Sd)
print("RSd_H", TDR_RSd)
print ("\n") 

Avarage_TDR = 1/(TDR_Imp + TDR_Pe + TDR_Sd + TDR_RSd)

CFI_Imp = Avarage_TDR * TDR_Imp
CFI_Pe = Avarage_TDR * TDR_Pe
CFI_Sd = Avarage_TDR * TDR_Sd
CFI_RSd = Avarage_TDR * TDR_RSd
        
print("CFI:")
print("Imp_H", CFI_Imp)
print("Pe_H", CFI_Pe)
print("Sd_H", CFI_Sd)
print("RSd_H", CFI_RSd)
print ("\n")        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        

