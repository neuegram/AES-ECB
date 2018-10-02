#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <cstdio>
#include <ios>
#include "aes.h"

int keysize;
uint8_t *key;
uint8_t *input;
long input_length;
char *out;
int mode;

uint8_t *read_file(char *filename) {
  // Open file
  FILE *pFile = fopen(filename, "r");
  if (pFile == nullptr) {
    throw std::ios_base::failure("Failure opening input file");
  }
  // Get file size
  fseek(pFile, 0, SEEK_END);
  long length = ftell(pFile);
  rewind(pFile);

  // Padding
  int old_length = length;
  if (length % 16 != 0) {
    length += 16 - (length % 16);
  }

  // Load input file into memory
  uint8_t *buf = (uint8_t*)malloc(sizeof(uint8_t)*length);
  if (buf == nullptr) {
    throw std::bad_alloc();
  }

  // Read input file into memory
  if (fread(buf, 1, old_length, pFile) != old_length) {
    throw std::ios_base::failure("Failure reading input file into memory");
  }

  // Padding
  if (length != old_length) {
    for (int i = old_length; i < length; i++) {
      buf[i] = (uint8_t)(length - old_length);
    }
  }

  // Close input file
  if (fclose(pFile)) {
    throw std::ios_base::failure("Failure closing input file");
  }

  input_length = length;
  return buf;
}

void write_file(char *filename, uint8_t *buf, size_t length) {
  FILE *pFile = fopen(filename, "w");
  if (pFile == nullptr) {
    throw std::ios_base::failure("Failure opening output file");
  }

  if (fwrite(buf , sizeof(uint8_t), length, pFile) != length) {
    throw std::ios_base::failure("Failure writing to output file from memory");
  }

  if (fclose(pFile)) {
    throw std::ios_base::failure("Failure closing input file");
  }

}


void parse_opts(int argc, char *argv[]) {
  const char* short_opts = "s:k:i:o:m:";
  const struct option long_opts[] = {
      {"keysize", required_argument, nullptr, 's'},
      {"keyfile", required_argument, nullptr, 'k'},
      {"inputfile", required_argument, nullptr, 'i'},
      {"outputfile", required_argument, nullptr, 'o'},
      {"mode", required_argument, nullptr, 'm'},
  };

  // Parse command line options
  int opt;
  while ((opt = getopt_long(argc, argv, short_opts, long_opts, nullptr)) != -1) {
    switch (opt) {
      case 's':
        if (optarg) {
          keysize = atoi(optarg);
        }
        break;
      case 'k':
        if (optarg) {
          key = read_file(optarg);
        }
        break;
      case 'i':
        if (optarg) {
          input = read_file(optarg);
        }
        break;
      case 'o':
        if (optarg) {
          out = optarg;
        }
        break;
      case 'm':
        if (optarg) {
          if (strcmp(optarg, "encrypt") == 0) {
            mode = 0;
          } else if (strcmp(optarg, "decrypt") == 0) {
            mode = 1;
          }
        }
        break;
      default:
        break;
    }
  }
}

int main(int argc, char *argv[]) {
  try {
    parse_opts(argc, argv);

    if (keysize % 8 == 0) {
      keysize /= 8;
    } else {
      throw std::invalid_argument("Invalid keysize");
    }

    AES *cipher = new AES(key, keysize);

    if (mode == 0) {
      for (int i = 0; i < input_length / 16; i++) {
        cipher->encryptECB(input + (i*16));
      }
    } else if (mode == 1) {
      for (int i = 0; i < input_length / 16; i++) {
        cipher->decryptECB(input + (i*16));
      }
      // Padding
      if (input[input_length-1] > 0 && input[input_length-1] < 16) {
        input_length -= input[input_length-1];
      }
    } else {
      throw std::invalid_argument("Invalid mode");
    }
    write_file(out, input, (size_t)input_length);

  } catch (const std::exception &ex) {
    printf("[*] Exception : %s", ex.what());
  }
}
