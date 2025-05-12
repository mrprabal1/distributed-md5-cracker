#include "md5.hpp"
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

static const unsigned char PADDING[64] = { 0x80 };

static const unsigned int MD5_T[64] = {
    // Standard MD5 constants
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0x4e0811a1, 0xf75c7e21, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8
};

void MD5::MD5_Init(MD5_CTX* context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

void MD5::MD5_Update(MD5_CTX* context, const unsigned char* input, unsigned int input_len) {
    unsigned int i = 0;
    unsigned int index = (context->count[0] >> 3) & 0x3F;
    unsigned int part_len = 64 - index;

    context->count[0] += input_len << 3;
    if (context->count[0] < (input_len << 3)) context->count[1]++;
    context->count[1] += input_len >> 29;

    if (input_len >= part_len) {
        memcpy(&context->buffer[index], input, part_len);
        MD5_Transform(context->state, context->buffer);
        for (i = part_len; i + 63 < input_len; i += 64)
            MD5_Transform(context->state, &input[i]);
        index = 0;
    }

    memcpy(&context->buffer[index], &input[i], input_len - i);
}

void MD5::MD5_Final(unsigned char digest[16], MD5_CTX* context) {
    unsigned char bits[8];
    unsigned int index, pad_len;

    Encode(bits, context->count, 8);
    index = (context->count[0] >> 3) & 0x3F;
    pad_len = (index < 56) ? (56 - index) : (120 - index);
    MD5_Update(context, PADDING, pad_len);
    MD5_Update(context, bits, 8);
    Encode(digest, context->state, 16);
    memset(context, 0, sizeof(*context));
}

void MD5::MD5_Transform(unsigned int state[4], const unsigned char block[64]) {
    unsigned int a = state[0], b = state[1], c = state[2], d = state[3];
    unsigned int x[16];
    Decode(x, block, 64);

    for (int i = 0; i < 64; i++) {
        unsigned int f, g;
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; }

        unsigned int temp = d;
        d = c;
        c = b;
        b = b + ((a + f + MD5_T[i] + x[g]) << 7 | (a + f + MD5_T[i] + x[g]) >> (32 - 7));
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5::Encode(unsigned char* output, unsigned int* input, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

void MD5::Decode(unsigned int* output, const unsigned char* input, unsigned int len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[i] = ((unsigned int)input[j]) |
                    ((unsigned int)input[j + 1] << 8) |
                    ((unsigned int)input[j + 2] << 16) |
                    ((unsigned int)input[j + 3] << 24);
    }
}

std::string MD5::hash(const std::string& input) {
    MD5_CTX context;
    unsigned char digest[16];
    MD5_Init(&context);
    MD5_Update(&context, reinterpret_cast<const unsigned char*>(input.c_str()), input.length());
    MD5_Final(digest, &context);

    std::stringstream ss;
    for (int i = 0; i < 16; i++)
        ss << std::setw(2) << std::setfill('0') << std::hex << (int)digest[i];
    return ss.str();
}

