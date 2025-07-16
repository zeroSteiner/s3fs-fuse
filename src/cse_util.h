#ifndef CSE_UTIL_H_
#define CSE_UTIL_H_

#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_IV_LENGTH  12

namespace CseUtil {

std::vector<unsigned char>* base64_decode(const std::string& encoded);

// todo check if IV and tag length are always the same size
std::vector<unsigned char>* decrypt_aes_gcm(
    const std::vector<unsigned char>& key,
	const std::array<unsigned char, AES_GCM_IV_LENGTH>& iv,
	std::array<unsigned char, AES_GCM_TAG_LENGTH>& tag,
	const std::vector<unsigned char>& ciphertext,
	const std::vector<unsigned char>* aad,
	bool padding
);

std::vector<unsigned char>* decrypt_cek(
    const std::string& encrypted_cek_b64,
    const std::vector<unsigned char>& kek
);
}

#endif
