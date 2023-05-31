import ssdeep
import pefile
import pehash
import hashlib
from difflib import SequenceMatcher
def calculate_character_similarity(string1, string2):
    # Đảm bảo hai chuỗi có cùng độ dài
    if len(string1) != len(string2):
        raise ValueError("Hai chuỗi cần có cùng độ dài để so sánh ký tự.")

    total_characters = len(string1)
    matching_characters = 0

    # Đếm số ký tự giống nhau
    for i in range(total_characters):
        if string1[i] == string2[i]:
            matching_characters += 1

    # Tính độ tương tự bằng phần trăm
    similarity_ratio = (matching_characters / total_characters) * 100

    return similarity_ratio
def calculate_similarity(string1, string2):
    # Tạo đối tượng SequenceMatcher với hai chuỗi đầu vào
    matcher = SequenceMatcher(None, string1, string2)

    # Tính độ tương đồng bằng phần trăm
    similarity_ratio = matcher.ratio() * 100

    return similarity_ratio

def calculate_md5(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        md5_hash = hashlib.md5(data).hexdigest()
        return md5_hash

def calculate_sha256(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        sha256_hash = hashlib.sha256(data).hexdigest()
        return sha256_hash

def calculate_sha1(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        sha1_hash = hashlib.sha1(data).hexdigest()
        return sha1_hash

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
    except pefile.PEFormatError:
        return "Invalid file"
#path = "./calc.exe"
path = "/home/kali/CoChe/step4/1000_second_files/clean_files_2/103836"
# Tinh MD, SHA1, SHA256
md5_result = calculate_md5(path)
sha1_result = calculate_sha1(path)
sha256_result = calculate_sha256(path)

# Tinh ssdeep
ssdeep_result = ssdeep.hash_from_file(path)

# Tinh pehash
pehash_result = pehash.totalhash_hex(path)


# Tinh imhash
pe = pefile.PE(path)
imhash_result = pe.get_imphash()

#Tinh resource_hash
src_ssdeep_result = calculate_resource_ssdeep_hash(path)

print("Original Value: ")
print("MD5:\t\t\t",md5_result)
print("SHA1:\t\t\t",sha1_result)
print("SHA256:\t\t\t",sha256_result)
print("SSdeep:\t\t\t",ssdeep_result)
print("PeHash:\t\t\t",pehash_result)
print("Imhash:\t\t\t",imhash_result)
print("Resource SSdeep:\t",src_ssdeep_result)
print("\n")

path = "./calc_modify.exe"

# Tinh MD, SHA1, SHA256
md5_mod_result = calculate_md5(path)
sha1_mod_result = calculate_sha1(path)
sha256_mod_result = calculate_sha256(path)

# Tinh ssdeep
ssdeep_mod_result = ssdeep.hash_from_file(path)

# Tinh pehash
pehash_mod_result = pehash.totalhash_hex(path)


# Tinh imhash
pe = pefile.PE(path)
imhash_mod_result = pe.get_imphash()

#Tinh resource_hash
src_ssdeep_mod_result = calculate_resource_ssdeep_hash(path)

print("Edited Value: ")
print("MD5:\t\t\t",md5_mod_result)
print("SHA1:\t\t\t",sha1_mod_result)
print("SHA256:\t\t\t",sha256_mod_result)
print("SSdeep:\t\t\t",ssdeep_mod_result)
print("PeHash:\t\t\t",pehash_mod_result)
print("Imhash:\t\t\t",imhash_mod_result)
print("Resource SSdeep:\t",src_ssdeep_mod_result)
print("\n")


#print("Match: ")
#print("MD5:\t",calculate_similarity(md5_mod_result, md5_result))
#print("SHA1:\t",calculate_similarity(sha1_mod_result, sha1_result))
#print("SHA256:\t",calculate_similarity(sha256_mod_result, sha256_result))
#print("SSdeep:\t",calculate_similarity(ssdeep_mod_result, ssdeep_result))
#print(src_ssdeep_result)
#print(src_ssdeep_result1)
#print("Imhash:\t",calculate_similarity(imhash_mod_result, imhash_result))
#print("PeHash:\t",calculate_similarity(pehash_mod_result, pehash_result))
#print("\n")


print("Match: ")
print("MD5:\t\t\t",calculate_character_similarity(md5_mod_result, md5_result))
print("SHA1:\t\t\t",calculate_character_similarity(sha1_mod_result, sha1_result))
print("SHA256:\t\t\t",calculate_character_similarity(sha256_mod_result, sha256_result))
print("SSdeep:\t\t\t",ssdeep.compare(ssdeep_mod_result, ssdeep_result))
print("Imhash:\t\t\t",calculate_character_similarity(imhash_mod_result, imhash_result))
print("PeHash:\t\t\t",calculate_character_similarity(pehash_mod_result, pehash_result))
print("Resource SSdeep:\t",ssdeep.compare(src_ssdeep_mod_result,src_ssdeep_result))
print("\n")

#print("PeHash:\t",calculate_character_similarity("384:5u3Smmq6aYaBpYFAfjhXrToHWS4mW4sme9V:Avmq6affYFAfjhr8sgE", "384:5u3Smmq6aYaBpYFmfjhXrToHWS4mW4sme9V:Avmq6affYFmfjhr8sgE"))



