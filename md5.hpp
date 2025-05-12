#ifndef MD5_HPP
#define MD5_HPP

#include <string>

class MD5 {
public:
    static std::string hash(const std::string& input);
private:
    typedef struct {
        unsigned int state[4];
        unsigned int count[2];
        unsigned char buffer[64];
    } MD5_CTX;

    static void MD5_Init(MD5_CTX* context);
    static void MD5_Update(MD5_CTX* context, const unsigned char* input, unsigned int input_len);
    static void MD5_Final(unsigned char digest[16], MD5_CTX* context);
    static void MD5_Transform(unsigned int state[4], const unsigned char block[64]);
    static void Encode(unsigned char* output, unsigned int* input, unsigned int len);
    static void Decode(unsigned int* output, const unsigned char* input, unsigned int len);
};

#endif // MD5_HPP

