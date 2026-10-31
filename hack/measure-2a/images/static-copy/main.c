#include <brotli/decode.h>
#include <stdint.h>
#include <unistd.h>

/* Decode a few bytes, which pulls the decoder into the binary, then wait: a Deployment needs a process that
   stays alive, and the image has no sleep. */
int main(void) {
    static const uint8_t encoded[] = {0x3b};  /* the encoding of an empty stream */
    uint8_t decoded[8];
    size_t size = sizeof decoded;
    volatile BrotliDecoderResult result = BrotliDecoderDecompress(sizeof encoded, encoded, &size, decoded);
    (void)result;
    for (;;) {
        pause();
    }
}
