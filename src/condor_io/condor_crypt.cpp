/***************************************************************
 *
 * Copyright (C) 1990-2007, Condor Team, Computer Sciences Department,
 * University of Wisconsin-Madison, WI.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/


#include "condor_common.h"
#include "condor_crypt.h"
#include "condor_md.h"
#include "condor_random_num.h"
#include "condor_auth_passwd.h"
#include <openssl/rand.h>              // SSLeay rand function
#include "condor_debug.h"

#include "condor_crypt_aesgcm.h"

Condor_Crypto_State::Condor_Crypto_State(Protocol proto, KeyInfo &key) :
    m_keyInfo(key)
{
    // m_keyInfo (initialized above) stores the key object,
    // which includes: protocol, len, data, duration

    // zero everything;
    enc_ctx = nullptr;
    dec_ctx = nullptr;

    // there should probably be a static function in each crypto object to do
    // these conversions so that the state object doesn't need any specifc
    // method manipulation here.

    switch(proto) {
        case CONDOR_3DES: {
            // reset() will initialize everything else
            break;
        }
        case CONDOR_BLOWFISH: {
            // reset() will initialize everything else
            break;
        }
        case CONDOR_AESGCM: {
            // AESGCM provides a method to init the StreamCryptoState object, use that.
            Condor_Crypt_AESGCM::initState(&m_stream_crypto_state);
            break;
        }
        default:
            dprintf(D_ALWAYS, "CRYPTO: WARNING: Initialized crypto state for unknown proto %i.\n", proto);
            break;
    }

    // initialize contexts for BLOWFISH and 3DES
    reset();

}

Condor_Crypto_State::~Condor_Crypto_State() {
	if(enc_ctx) EVP_CIPHER_CTX_free(enc_ctx);
	if(dec_ctx) EVP_CIPHER_CTX_free(dec_ctx);
}

void Condor_Crypto_State::reset() {
	const EVP_CIPHER *cipher_type = nullptr;
	switch(m_keyInfo.getProtocol()) {
	case CONDOR_3DES:
		cipher_type = EVP_des_ede3_cfb64();
		break;
	case CONDOR_BLOWFISH:
		cipher_type = EVP_bf_cfb64();
		break;
	case CONDOR_AESGCM:
	default:
		// Do nothing
		break;
	}
	if (cipher_type) {
		// Intialize the ivec with all zeros
		unsigned char ivec[8] = { };

		// (re)initialize the cipher context
		if(enc_ctx) EVP_CIPHER_CTX_free(enc_ctx);
		if(dec_ctx) EVP_CIPHER_CTX_free(dec_ctx);
		enc_ctx = EVP_CIPHER_CTX_new();
		dec_ctx = EVP_CIPHER_CTX_new();

		EVP_EncryptInit_ex(enc_ctx, cipher_type, NULL, NULL, NULL);
		EVP_CIPHER_CTX_set_key_length(enc_ctx, m_keyInfo.getKeyLength());
		EVP_EncryptInit_ex(enc_ctx, NULL, NULL, m_keyInfo.getKeyData(), ivec);

		EVP_DecryptInit_ex(dec_ctx, cipher_type, NULL, NULL, NULL);
		EVP_CIPHER_CTX_set_key_length(dec_ctx, m_keyInfo.getKeyLength());
		EVP_DecryptInit_ex(dec_ctx, NULL, NULL, m_keyInfo.getKeyData(), ivec);
	}
}

int Condor_Crypt_Base :: encryptedSize(int inputLength, int blockSize)
{
    int size = inputLength % blockSize;
    return (inputLength + ((size == 0) ? blockSize : (blockSize - size)));
}

unsigned char * Condor_Crypt_Base :: randomKey(int length)
{
    unsigned char * key = (unsigned char *)(malloc(length));

    memset(key, 0, length);

    static bool already_seeded = false;
    int size = 128;
    if( ! already_seeded ) {
        unsigned char * buf = (unsigned char *) malloc(size);
        ASSERT(buf);
		// Note that RAND_seed does not seed, but rather simply
		// adds entropy to the pool that is initialized with /dev/urandom
		// (actually, this could potentially help in the case where HTCondor
		// is running on a system without /dev/urandom; seems ... unlikely for
		// Linux!).
		//
		// As this only helps the pool, we are OK with calling the 'insecure'
		// variant here.
		for (int i = 0; i < size; i++) {
			buf[i] = get_random_int_insecure() & 0xFF;
		}

        RAND_seed(buf, size);
        free(buf);
		already_seeded = true;
    }

    RAND_bytes(key, length);
    return key;
}

char *Condor_Crypt_Base::randomHexKey(int length)
{
	unsigned char *bytes = randomKey(length);
	char *hex = (char *)malloc(length*2+1);
	ASSERT( hex );
	int i;
	for(i=0; i<length; i++) {
		sprintf(hex+i*2,"%02x",bytes[i]);
	}
	free(bytes);
	return hex;
}

unsigned char * Condor_Crypt_Base :: oneWayHashKey(const char * initialKey)
{
    return Condor_MD_MAC::computeOnce((const unsigned char *)initialKey, strlen(initialKey));
}

unsigned char * Condor_Crypt_Base::hkdf(const unsigned char *initialKey, size_t input_key_len, size_t output_key_len)
{
	auto result = static_cast<unsigned char *>(malloc(output_key_len));
	if (!result) return nullptr;

	auto retval = Condor_Auth_Passwd::hkdf(initialKey, input_key_len,
		reinterpret_cast<const unsigned char *>("htcondor"), strlen("htcondor"),
		reinterpret_cast<const unsigned char *>("keygen"), strlen("keygen"),
		result, output_key_len);

	if (retval < 0) {
		free(result);
		return nullptr;
	}
	return result;
}
