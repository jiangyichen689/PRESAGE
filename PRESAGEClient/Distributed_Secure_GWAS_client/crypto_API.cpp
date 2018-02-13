
#include "crypto_API.h"

static CryptoPP::PNew s_pNew = NULL;  
static CryptoPP::PDelete s_pDelete = NULL;  
  
extern "C" __declspec(dllexport)  
inline void __cdecl SetNewAndDeleteFromCryptoPP(  
    CryptoPP::PNew pNew,  
    CryptoPP::PDelete pDelete,  
    CryptoPP::PSetNewHandler pSetNewHandler)  
{  
    s_pNew = pNew;  
    s_pDelete = pDelete;  
}  
  
inline void * __cdecl operator new (size_t size)  
{  
    return s_pNew(size);  
}  
  
inline void __cdecl operator delete (void * p)  
{  
    s_pDelete(p);  
}  

void trust_covert_endian_32bits(const uint32_t *key_in, uint32_t * key_out, int key_size){
	for(int i = 0; i < key_size; i++){
		key_out[key_size-1-i] = key_in[i];
	}
}

bool test_verify_MSG(const uint8_t *p_data, 
                     uint32_t data_size,
					 trust_ec256_ECDSA_public_t *p_public,
					 const uint8_t *signature,
					 uint32_t signature_size){
	ECDSA<ECP, CryptoPP::SHA256>::PublicKey pubKey;
	uint8_t *tmp1 = (uint8_t *) malloc(2*sizeof(p_public->gx));
	trust_covert_endian(p_public->gx, tmp1, sizeof(p_public->gx));
	trust_covert_endian(p_public->gy, tmp1+sizeof(p_public->gx), sizeof(p_public->gx));
	
	ECP::Point p;
	int aa = sizeof(p_public->gx);
	p.identity = false;
	p.x.Decode(tmp1, sizeof(p_public->gx));
	p.y.Decode(tmp1+sizeof(p_public->gx), sizeof(p_public->gx));
	
	pubKey.Initialize(CryptoPP::ASN1::secp256r1(), p);
	//pubKey.SetPublicElement(p);
	cout << "X: " <<std::hex << pubKey.GetPublicElement().x <<endl;
	cout << "Y: " <<std::hex << pubKey.GetPublicElement().y <<endl;//*/
	AutoSeededRandomPool prng;
	bool result2 = pubKey.Validate( prng, 3 );

    ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier( pubKey );
	uint8_t * tmp2 = (uint8_t*) malloc(signature_size);
	trust_covert_endian((uint8_t *)signature, (uint8_t *)tmp2, 32);
	trust_covert_endian((uint8_t *)signature+32, (uint8_t *)tmp2+32, 32);
	//trust_covert_endian((uint8_t *)signature, (uint8_t *)tmp1, 64);

    bool result = verifier.VerifyMessage( (const byte*)p_data, data_size, tmp2, signature_size);
    if(result)
        cout << "Verified signature on message" << endl;
    else
        cout << "Failed to verify signature on message" << endl;
	return result;

}
trust_status_t trust_ecdsa_sign(const uint8_t *p_data, 
                                uint32_t data_size,  
                                trust_ec256_ECDSA_private_t *p_private, 
                                trust_ec256_signature_t *p_signature)
{
	AutoSeededRandomPool prng;
	ECDSA<ECP, CryptoPP::SHA256>::PrivateKey privKey;
	
	Integer b;
	uint8_t *tmp = (uint8_t *) malloc(sizeof(p_private->r));
	trust_covert_endian(p_private->r, tmp, sizeof(p_private->r));
	b.Decode(tmp, sizeof(p_private->r));
	privKey.SetPrivateExponent(b);
#if defined DEBUG_CRYPTO
	cout << "" <<std::hex << privKey.GetPrivateExponent() <<endl;
#endif
	// Load private key (in ByteQueue, PKCS#8 format)
	privKey.Initialize(CryptoPP::ASN1::secp256r1(), b); 
	bool result1 = privKey.Validate( prng, 3 );
	ECDSA<ECP, CryptoPP::SHA256>::Signer signer( privKey );

    // Determine maximum size, allocate a string with that size
    size_t siglen = signer.MaxSignatureLength();
    string signature(siglen, 0x00);

    // Sign, and trim signature to actual size
    siglen = signer.SignMessage( prng, (const byte*)p_data, data_size, (byte*)signature.data() );
    signature.resize(siglen);	

	SecByteBlock b1((byte *)signature.data(), signature.size());
	Integer c(b1.BytePtr(), siglen);
#if defined DEBUG_CRYPTO
	cout << "sig:" << std::hex << c << endl;
#endif
	uint8_t *tt = b1.BytePtr();
	
	trust_covert_endian((uint8_t *)b1.BytePtr(), (uint8_t *)p_signature->x, 32);
	trust_covert_endian((uint8_t *)b1.BytePtr()+32, (uint8_t *)p_signature->y, 32);
	 
	return TRUST_SUCCESS;
}


trust_status_t trust_ecc256_open_context()
{
	if (!FIPS_140_2_ComplianceEnabled())
	{
		fprintf(stderr, "FIPS 140-2 compliance was turned off at compile time.\n");
		abort();
	}
	DoDllPowerUpSelfTest();
	// check self test status
	if (GetPowerUpSelfTestStatus() != POWER_UP_SELF_TEST_PASSED)// by wwj
	{
		fprintf(stderr, "Automatic power-up self test failed.\n");
		abort();
	}
	//cout << "0. Automatic power-up self test passed.\n";
	return TRUST_SUCCESS;
}

void trust_covert_key_2_sgx(const Integer& key, byte * key_sgx, int key_size){
	//cout << " " << std::hex << key << endl; 
    std::stringstream buffer; 
	buffer << std::hex << key << endl; 
	HexDecoder decoder;
	decoder.Put( (byte*)buffer.str().data(), buffer.str().size() );
	decoder.MessageEnd();
	decoder.Get(key_sgx, key_size);
	for(int i = 0; i < key_size/2; i++){
		uint8_t temp1 = key_sgx[i];
		key_sgx[i] = key_sgx[key_size - 1 -i];
		key_sgx[key_size - 1 -i] = temp1;
	}
}

void trust_covert_endian(const byte *key_in, byte * key_out, int key_size){
	for(int i = 0; i < key_size; i++){
		key_out[key_size-1-i] = key_in[i];
	}
}

trust_status_t trust_ecc256_create_key_pair_ECDH(trust_ec256_ECDH_private_t *p_private,
                                        trust_ec256_ECDH_public_t *p_public)
{
	trust_status_t result = TRUST_SUCCESS;
	OID CURVE = secp256r1();
    AutoSeededX917RNG<AES> rng;
    ECDH < ECP >::Domain dhB( CURVE );
	p_private->dhB = dhB;
    // Don't worry about point compression. Its amazing that Certicom got
    // a patent for solving an algebraic equation....
    // dhA.AccessGroupParameters().SetPointCompression(true);
    // dhB.AccessGroupParameters().SetPointCompression(true);

    //SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
	p_private->privKey.New(p_private->dhB.PrivateKeyLength());
	p_public->pubKey.New(p_private->dhB.PublicKeyLength());
	int a = p_private->dhB.PrivateKeyLength();
	int b = p_private->dhB.PublicKeyLength();
    //dhA.GenerateKeyPair(rng, privA, pubA);
    p_private->dhB.GenerateKeyPair(rng, p_private->privKey, p_public->pubKey);

	//decoder.Get((byte*)&p_private->r, sizeof(p_private->r));
	trust_covert_endian(p_private->privKey.BytePtr(), (byte*)&p_private->r, sizeof(p_private->r));
	trust_covert_endian(p_public->pubKey.BytePtr()+1, (byte*)&p_public->gx, sizeof(p_public->gx)); // there is a common prefix 04 in pubKey
	trust_covert_endian(p_public->pubKey.BytePtr()+sizeof(p_public->gx)+1, (byte*)&p_public->gy, sizeof(p_public->gy));
	return result;
}

trust_status_t trust_ecc256_compute_shared_dhkey(trust_ec256_ECDH_private_t *p_privateB,
												 trust_ec256_ECDH_public_t  *publicA,
												 trust_ec256_dh_shared_t    *trust_dh_key)
{
	trust_status_t result = TRUST_SUCCESS;
	SecByteBlock sharedB(p_privateB->dhB.AgreedValueLength());
	SecByteBlock pubA;
	uint8_t *publicA_tmp = (uint8_t*)malloc(p_privateB->dhB.PublicKeyLength());
	publicA_tmp[0] = 0x04;

	// convert little to big endian
	trust_covert_endian((byte*)&publicA->gx, &publicA_tmp[1], sizeof(publicA->gx));
	trust_covert_endian((byte*)&publicA->gy, &publicA_tmp[1+sizeof(publicA->gx)], sizeof(publicA->gy));

	pubA.Assign((uint8_t*)publicA_tmp, p_privateB->dhB.PublicKeyLength());
	const bool rtn2 = p_privateB->dhB.Agree(sharedB, p_privateB->privKey, pubA);
	if(!rtn2)
		throw runtime_error("Failed to reach shared secret (A)");
	/*Integer b;
	b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    cout << "(B): " << std::hex << b << endl;*/
	// convert big to little endian
	//uint8_t * a = sharedB.BytePtr();
	trust_covert_endian(sharedB.BytePtr(), (byte *)trust_dh_key, sizeof(trust_dh_key->s));
	//memcpy_s(sharedB.BytePtr(), sizeof(trust_dh_key->s), trust_dh_key, sizeof(trust_dh_key->s));
	p_privateB->sharedKey = sharedB;
	return result;
}

trust_status_t trust_rijndael128_cmac_msg(uint8_t *cmac_key,  // 128 bit key
        uint8_t *p_data_buf,
        int buf_size,
        uint8_t *data_mac) // 128 bit output
{
	trust_status_t result = TRUST_SUCCESS; 
	string mac;
	SecByteBlock key((byte *)cmac_key, TRUST_CMAC_KEY_SIZE);
	string plain((char*)p_data_buf, buf_size);
	CMAC< AES > cmac(key, key.size());		
		StringSource(plain, true, 
			new HashFilter(cmac,
				new StringSink(mac)
			) // HashFilter      
		); // StringSource
	memcpy_s(data_mac, TRUST_CMAC_KEY_SIZE, mac.data(),TRUST_CMAC_KEY_SIZE);
	return TRUST_SUCCESS;
}

trust_status_t trust_ecc256_create_key_pair_ECDSA(trust_ec256_ECDSA_private_t *p_private,
                                        trust_ec256_ECDSA_public_t *p_public)
{
	trust_status_t result = TRUST_SUCCESS; 
	result = GeneratePrivateKey_ECDSA( CryptoPP::ASN1::secp256r1(), p_private->privateKey);
	if( TRUST_SUCCESS != result ) { return TRUST_FAILURE; }
	//decoder.Get((byte*)&p_private->r, sizeof(p_private->r));
	trust_covert_key_2_sgx(p_private->privateKey.GetPrivateExponent(), (byte*)&p_private->r, sizeof(p_private->r));
	
	result = GeneratePublicKey_ECDSA(p_private->privateKey, p_public->publicKey);
	trust_covert_key_2_sgx(p_public->publicKey.GetGroupParameters().GetSubgroupGenerator().x, (byte*)&p_public->gx, sizeof(p_public->gx));
	trust_covert_key_2_sgx(p_public->publicKey.GetGroupParameters().GetSubgroupGenerator().y, (byte*)&p_public->gy, sizeof(p_public->gx));

    assert( true == result );
    if( TRUST_SUCCESS != result ) { return TRUST_FAILURE; }
	return TRUST_SUCCESS;
}

trust_status_t GeneratePrivateKey_ECDSA( const OID& oid, ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key )
{
    AutoSeededRandomPool prng;

    key.Initialize( prng, oid ); 
    assert( key.Validate( prng, 3 ) );

	if(key.Validate( prng, 3 ))
		return TRUST_SUCCESS;
	else
		return TRUST_FAILURE;
}

trust_status_t GeneratePublicKey_ECDSA( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& privateKey, ECDSA<ECP, CryptoPP::SHA256>::PublicKey& publicKey )
{
    AutoSeededRandomPool prng;

    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );

    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );
	if(publicKey.Validate( prng, 3 ))
		return TRUST_SUCCESS;
	else
		return TRUST_FAILURE;
}

void PrintDomainParameters( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
	cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}

void PrintPrivateKey( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key )
{   
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << std::hex <<key.GetPrivateExponent() << endl; 
}

void PrintPublicKey( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key )
{   
    cout << endl;
    cout << "Public Element:" << endl;
	cout << " pubkey: " << std::hex <<key.GetPublicElement().x << std::hex <<key.GetPublicElement().y << endl; 
	cout << " X: " << std::hex <<key.GetPublicElement().x << endl; 
    cout << " Y: " << std::hex <<key.GetPublicElement().y << endl;
}

void SavePrivateKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key )
{
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void SavePublicKey( const string& filename, const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key )
{   
    key.Save( FileSink( filename.c_str(), true /*binary*/ ).Ref() );
}

void LoadPrivateKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key )
{   
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

void LoadPublicKey( const string& filename, ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key )
{
    key.Load( FileSource( filename.c_str(), true /*pump all*/ ).Ref() );
}

bool SignMessage( const ECDSA<ECP, CryptoPP::SHA256>::PrivateKey& key, const string& message, string& signature )
{
    AutoSeededRandomPool prng;
    
    signature.erase();    

    StringSource( message, true,
        new SignerFilter( prng,
            ECDSA<ECP,CryptoPP::SHA256>::Signer(key),
            new StringSink( signature )
        ) // SignerFilter
    ); // StringSource
    
    return !signature.empty();
}

bool VerifyMessage( const ECDSA<ECP, CryptoPP::SHA256>::PublicKey& key, const string& message, const string& signature )
{
    bool result = false;

    StringSource( signature+message, true,
        new SignatureVerificationFilter(
            ECDSA<ECP,CryptoPP::SHA256>::Verifier(key),
            new ArraySink( (byte*)&result, sizeof(result) )
        ) // SignatureVerificationFilter
    );

    return result;
}

bool trust_rijndael128GCM_decrypt(const trust_ec_key_128bit_t *key,
                                 const uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 const uint8_t *p_in_mac)
{
    //KEY 0000000000000000000000000000000000000000000000000000000000000000
    //IV  000000000000000000000000
    //HDR 00000000000000000000000000000000
    //PTX 00000000000000000000000000000000
    //CTX cea7403d4d606b6e074ec5d3baf39d18
    //TAG ae9b1771dba9cf62b39be017940330b4

    // Test Vector 003
    //byte key[32];
    //memset( key, 0, sizeof(key) );
    //byte iv[12];
    //memset( iv, 0, iv_len );

    //string adata( 16, (char)0x00 );
    //string pdata( 16, (char)0x00 );

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string rpdata;

    try
    {
        GCM< AES >::Decryption d;
		int a = sizeof(*key);
        d.SetKeyWithIV((byte*)key, sizeof(*key), (byte*)iv, iv_len);

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc((char*)p_src, src_len);
        string mac((char*)p_in_mac, TAG_SIZE);

        // Sanity checks
        //assert( cipher.size() == enc.size() + mac.size() );
        //assert( enc.size() == pdata.size() );
        //assert( TAG_SIZE == sizeof(*p_in_mac) );

        // Not recovered - sent via clear channel
        string radata((char*)p_aad, aad_len);     

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)radata.data(), radata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert( true == b );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }

		// need to check the buffer size. currently the buffer is 256
		memcpy_s(p_dst, n, retrieved.data(),n);

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        //cout << "Decrypted and Verified data. Ready for use." << endl;
        //cout << endl;

        //cout << "adata length: " << adata.size() << endl;
        //cout << "pdata length: " << pdata.size() << endl;
        //cout << endl;

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        //cout << "cipher text: " << endl << " " << encoded << endl;
        //cout << endl;

        //cout << "recovered data : " << retrieved << endl;
        //cout << "recovered pdata length: " << rpdata.size() << endl;
        //cout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/
    return true;
}


bool trust_rijndael128GCM_encrypt(trust_ec_key_128bit_t *key,
                                 uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 uint8_t *p_out_mac)
{
	string cipher, encoded;

	string adata((char*)p_aad, aad_len); 
    //string pdata((char*)p_src, src_len);

	const int TAG_SIZE = 16;
	 try
    {
		GCM< AES >::Encryption e;
        e.SetKeyWithIV((const byte*) key, sizeof(*key), (byte*)iv, iv_len );
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
		ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)p_src, src_len);
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
		

		//ef.Put( (const byte*)pdata.data(), pdata.size() );
		//ef.MessageEnd();


        // Pretty print
        //StringSource( cipher, true,
        //    new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
		//
		//// get enc and cipher

		string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );
		memcpy_s(p_dst, cipher.length()-TAG_SIZE, enc.data(),cipher.length()-TAG_SIZE);
		memcpy_s(p_out_mac, TAG_SIZE, mac.data(),TAG_SIZE);

    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

	
	/*char* temp = new char[src_len + 1];
	//char a = '\0';
	memcpy( temp, p_src, src_len);
	//memcpy( temp + src_len, &a, 1);
	string pdata(temp, src_len);
	string adata((char*)p_aad, aad_len);   

    const int TAG_SIZE = 16;
	string cipher;

    try
	{
        GCM< AES >::Encryption e;
		
		e.SetKeyWithIV((byte*)key, sizeof(*key), (byte*)iv, iv_len);

		AuthenticatedEncryptionFilter ef( e,
        new StringSink( cipher ), false,
        TAG_SIZE // MAC_AT_END 
		); // AuthenticatedEncryptionFilter
		
		//ef.ChannelPut( "AAD", (const byte*)(adata.data()), adata.size() );
		//ef.ChannelMessageEnd("AAD");
		
		
		ef.Put( (const byte*)pdata.data(), pdata.size() );
		ef.MessageEnd();
		//ef.SetRetrievalChannel();
	}

	catch( CryptoPP::Exception& e)
	{
		cerr << e.what() <<endl;
	} */
		

		//string enc = cipher.substr( 0, cipher.length() - TAG_SIZE);
		//string mac = cipher.substr( cipher.length() - TAG_SIZE);
		//printf( "cipher.length: %d\n", cipher.length());
		//printf( "src_leng:%d\n", src_len);
		//printf( "enc.lengh:%d\n", enc.length());
		//printf( "mac_length:%d\n", mac.length());

		
	 
	 /*delete temp;
	 printf( "end of function!\n");*/
	 return true;
}





bool trust_rijndael128GCM_encrypt_1(trust_ec_key_128bit_t *key,
                                 uint8_t *p_src,
                                 uint32_t src_len,
                                 uint8_t *p_dst,
                                 const uint8_t *iv,
                                 uint32_t iv_len,
                                 const uint8_t *p_aad,
                                 uint32_t aad_len,
                                 uint8_t *p_out_mac)
{
	string cipher, encoded;

	string adata((char*)p_aad, aad_len); 
    string pdata((char*)p_src, src_len);

	const int TAG_SIZE = 16;
	 try
    {
        GCM< AES >::Encryption e;
        e.SetKeyWithIV((const byte*) key, sizeof(*key), (byte*)iv, sizeof(*iv) );
        

		 StringSource ss1( pdata, true,
        new AuthenticatedEncryptionFilter( e,
            new StringSink( cipher ), false, TAG_SIZE
        ) // AuthenticatedEncryptionFilter
    );


        // Pretty print
        //StringSource( cipher, true,
          //  new HexEncoder( new StringSink( encoded ), true, 16, " " ) );

		// get enc and cipher

		string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );
		memcpy_s(p_dst, src_len, enc.data(),src_len);
		memcpy_s(p_out_mac, TAG_SIZE, mac.data(),TAG_SIZE);

    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
	return true;
}
