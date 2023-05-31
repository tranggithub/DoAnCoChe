import ssdeep
import pymysql
import os
import hashlib
import pefile
import lief
import pehash

def calculate_md5(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        md5_hash = hashlib.md5(data).hexdigest()
        return md5_hash
    
def calculate_pehash(file_path):
	pehash_result = pehash.totalhash_hex(file_path)
	return pehash_result

def calculate_imphash(file_path):
	pe = pefile.PE(file_path)

	# Tính toán ImpHash
	imphash = pe.get_imphash()

	return imphash
    
def calculate_ssdeep_hash(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    hash_value = ssdeep.hash(file_data)
    return hash_value
    
def calculate_resource_ssdeep_hash(file_path):
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

    
def insert_hash_to_database(file_path, md5_value, sd_h_value, pe_h_value, imp_h_value, rsd_h_value):
    conn = pymysql.connect(
        host='10.0.139.42',
        user='nhom13',
        password='123456',
        database='dataset'
    )
    cursor = conn.cursor()
    
    query = "INSERT INTO dataset1 (file_path, sd_h, md5, pe_h, imp_h, rsd_h) VALUES (%s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE sd_h = %s, md5 = %s, pe_h = %s, imp_h = %s, rsd_h = %s"
    values = (file_path, sd_h_value, md5_value, pe_h_value, imp_h_value, rsd_h_value, sd_h_value, md5_value, pe_h_value, imp_h_value, rsd_h_value)
    cursor.execute(query, values)
    
    conn.commit()
    
    cursor.close()
    conn.close()


folder_path = '/home/kali/Desktop/dataset1'

sd_h_output_file = '/home/kali/Desktop/sdh.txt'
md5_output_file = '/home/kali/Desktop/md5.txt'
pe_h_output_file = '/home/kali/Desktop/peh.txt'
imp_h_output_file = '/home/kali/Desktop/imph.txt'
rsd_h_output_file = '/home/kali/Desktop/rsdh.txt'

sd_h_file = open(sd_h_output_file, 'w')
md5_file = open(md5_output_file, 'w')
pe_h_file = open(pe_h_output_file, 'w')
imp_h_file = open(imp_h_output_file, 'w')
rsd_h_file = open(rsd_h_output_file, 'w')

for root, dirs, files in os.walk(folder_path):
    for file in files:
        try:
            file_path = os.path.join(root, file)
            sd_h_value = calculate_ssdeep_hash(file_path)
            md5_value = calculate_md5(file_path)
            pe_h_value = calculate_pehash(file_path)
            imp_h_value = calculate_imphash(file_path)
            rsd_h_value = calculate_resource_ssdeep_hash(file_path)
            
            if pe_h_value is not None and len(pe_h_value) > 0 and len(imp_h_value) > 0 and rsd_h_value != "3::":
                pe_h_row = f"{pe_h_value}\n"
                imp_h_row = f"{imp_h_value}\n"
                rsd_h_row = f"{rsd_h_value}\n"              
                sd_h_row = f"{sd_h_value}\n"
                md5_row = f"{md5_value}\n"

                sd_h_file.write(sd_h_row)
                md5_file.write(md5_row)
                rsd_h_file.write(rsd_h_row)
                imp_h_file.write(imp_h_row)
                pe_h_file.write(pe_h_row)
                insert_hash_to_database(file_path, md5_value, sd_h_value, pe_h_value, imp_h_value, rsd_h_value)
                print("Hash inserted for file:", file_path)
            else:
                os.remove(file_path)
        except Exception:
            print("Invalid file:", file_path)
            os.remove(file_path)
        
sd_h_file.close()
md5_file.close()
pe_h_file.close()
imp_h_file.close()
rsd_h_file.close()
