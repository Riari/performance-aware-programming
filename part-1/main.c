#include <direct.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 32
#define BITS 16

#define MASK_FIELD_DESTINATION 0x02
#define MASK_FIELD_WIDTH 0x01
#define MASK_FIELD_MODE 0xC0
#define MASK_FIELD_REGISTER 0x38
#define MASK_FIELD_REGISTER_MEMORY 0x07

#define MODE_MEMORY_NO_DISPLACEMENT 0x00
#define MODE_MEMORY_8BIT_DISPLACEMENT 0x01
#define MODE_MEMORY_16BIT_DISPLACEMENT 0x02
#define MODE_MEMORY_REGISTER 0x03

const char MNEMONIC_MOV[] = "MOV";

typedef enum {
    NONE,
    REG,
    REG_MEM,
    MEM,
    IMM8,
    IMM16,
    REL8,
    REL16,
    SEGMENT_REG
} OperandType;

typedef struct {
    uint8_t opcode;        // Base opcode byte (10001000 for MOV)
    uint8_t mask;          // Mask to match first 6 bits only (11111100)
    const char *mnemonic;  // Instruction mnemonic
    OperandType operand1;  // First operand type
    OperandType operand2;  // Second operand type
} Instruction;

const Instruction INSTRUCTION_TABLE[] = {
    {0x88, 0xFC, MNEMONIC_MOV, REG_MEM, REG}, // MOV r/m8, reg8 (d=0, w=0)
    {0x89, 0xFC, MNEMONIC_MOV, REG_MEM, REG}, // MOV r/m16, reg16 (d=0, w=1)
    {0x8A, 0xFC, MNEMONIC_MOV, REG, REG_MEM}, // MOV reg8, r/m8 (d=1, w=0)
    {0x8B, 0xFC, MNEMONIC_MOV, REG, REG_MEM}, // MOV reg16, r/m16 (d=1, w=1)
};

const char* REGISTER_TABLE_8BIT[] = {"AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"};
const char* REGISTER_TABLE_16BIT[] = {"AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"};

const Instruction* lookup_instruction(uint8_t byte) {
    for (int i = 0; i < sizeof(INSTRUCTION_TABLE) / sizeof(INSTRUCTION_TABLE[i]); ++i) {
        Instruction instruction = INSTRUCTION_TABLE[i];
        if ((byte & instruction.mask) == (instruction.opcode & instruction.mask)) {
            return &INSTRUCTION_TABLE[i];
        }
    }

    return NULL;
}

int byte_contains_mask(unsigned char byte, uint8_t mask) {
  return (byte & mask) == mask;
}

const char* get_register_name(uint8_t reg, uint8_t isWord) {
  return (isWord == 0)
    ? REGISTER_TABLE_8BIT[reg & 0x07]
    : REGISTER_TABLE_16BIT[reg & 0x07];
}

int append_formatted(char *buffer, size_t size, const char *format, ...) {
    size_t len = strlen(buffer);

    if (len >= size - 1) {
        return -1;
    }

    va_list args;
    va_start(args, format);

    int written = vsnprintf(buffer + len, size - len, format, args);

    va_end(args);

    return (written >= 0 && (size_t)written < size - len) ? written : -1;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    perror("Expected filename as argument.");
    return 1;
  }

  char* cwdBuffer;
  if ((cwdBuffer = _getcwd(NULL, 0)) == NULL) {
    perror("_getcwd error");
  } else {
    printf("%s \nLength:%zu\n", cwdBuffer, strlen(cwdBuffer));
    free(cwdBuffer);
  }

  printf("Opening file %s\n", argv[1]);

  FILE *file;
  fopen_s(&file, argv[1], "r");
  if (file == NULL) {
    perror("Could not open file.");
    fclose(file);
    return 1;
  }

  unsigned char fileBuffer[BUFFER_SIZE];
  size_t bytesRead = fread(fileBuffer, sizeof(unsigned char), BUFFER_SIZE, file);
  fclose(file);

  // TODO: "bits 16" tells the assembler the code is 16-bit. Maybe try to determine this automatically from the binary?
  //       I'm not sure if it's a standard directive or specific to NASM.
  char output[1024] = "bits 16\n\n";

  size_t i = 0;
  while (i < bytesRead) {
    unsigned char byte1 = fileBuffer[i++];

    const Instruction* instruction = lookup_instruction(byte1);

    append_formatted(output, sizeof(output), "%s ", instruction->mnemonic);

    if (instruction->mnemonic == MNEMONIC_MOV) {
      int isWord = byte_contains_mask(byte1, MASK_FIELD_WIDTH);
      int isDestination = byte_contains_mask(byte1, MASK_FIELD_DESTINATION);

      unsigned char byte2 = fileBuffer[i++];

      unsigned char reg = (byte2 & MASK_FIELD_REGISTER) >> 3;
      unsigned char rm = (byte2 & MASK_FIELD_REGISTER_MEMORY);

      const char* regName = get_register_name(reg, isWord);
      const char* rmName = get_register_name(rm, isWord);

      append_formatted(output, sizeof(output), "%s,%s\n", isDestination ? regName : rmName, isDestination ? rmName : regName);
    }
  }

  printf("%s", output);

  return 0;
}
