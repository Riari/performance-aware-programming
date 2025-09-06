#include <direct.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Instruction mnemonics
#define MNEMONIC_MOV "MOV"
#define MNEMONIC_ADD "ADD"
#define MNEMONIC_SUB "SUB"
#define MNEMONIC_CMP "CMP"
#define MNEMONIC_JMP "JMP"
#define MNEMONIC_CALL "CALL"
#define MNEMONIC_RET "RET"
#define MNEMONIC_PUSH "PUSH"
#define MNEMONIC_POP "POP"
#define MNEMONIC_AND "AND"
#define MNEMONIC_OR "OR"
#define MNEMONIC_XOR "XOR"
#define MNEMONIC_NOT "NOT"
#define MNEMONIC_SHL "SHL"
#define MNEMONIC_SHR "SHR"

// Operand types
#define OPERAND_REG "REG"   // Register
#define OPERAND_IMM "IMM"   // Immediate value
#define OPERAND_MEM "MEM"   // Memory reference
#define OPERAND_ADDR "ADDR" // Address (for jumps, calls)
#define OPERAND_SREG "SREG" // Segment register
#define OPERAND_NONE "NONE" // No operand

typedef struct InstructionNode {
  struct InstructionNode *children[2];

  bool isTerminal;

  struct {
    char *mnemonic;
    int operandCount;
    char *operandTypes[2];
    int bytes;
  } instruction;
} InstructionNode;

typedef struct DecodedInstruction {
  char mnemonic[16];
  char operands[2][32];
  int bytes;
} DecodedInstruction;

InstructionNode *create_node() {
  InstructionNode *node = (InstructionNode *)malloc(sizeof(InstructionNode));
  node->children[0] = NULL;
  node->children[1] = NULL;
  node->isTerminal = false;

  return node;
}

DecodedInstruction *decode_instruction(InstructionNode *root,
                                       const uint8_t *bytes, int maxLength) {
  InstructionNode *current = root;
  InstructionNode *lastMatch = NULL;

  int bitsConsumed = 0;
  int byteIndex = 0;

  while (byteIndex < maxLength && current) {
    uint8_t currentByte = bytes[byteIndex];

    for (int bit = 7; bit >= 0; bit--) {
      int bitValue = (currentByte >> bit) & 1;

      if (!current->children[bitValue])
        break; // Dead end

      current = current->children[bitValue];
      bitsConsumed++;

      if (current->isTerminal)
        lastMatch = current;
    }

    byteIndex++;

    if (byteIndex * 8 < bitsConsumed)
      break;
  }

  if (!lastMatch)
    return NULL; // No match

  DecodedInstruction *result =
      (DecodedInstruction *)malloc(sizeof(DecodedInstruction));
  strcpy(result->mnemonic, lastMatch->instruction.mnemonic);

  for (int i = 0; i < lastMatch->instruction.operandCount; i++) {
    strcpy(result->operands[i], lastMatch->instruction.operandTypes[i]);
  }

  result->bytes = lastMatch->instruction.bytes;

  return result;
}

const char *REGISTER_TABLE_8BIT[8] = {"AL", "CL", "DL", "BL",
                                      "AH", "CH", "DH", "BH"};
const char *REGISTER_TABLE_16BIT[8] = {"AX", "CX", "DX", "BX",
                                       "SP", "BP", "SI", "DI"};

char *decode_register(uint8_t regCode, bool is16bit) {
  if (is16bit)
    return strdup(REGISTER_TABLE_16BIT[regCode]);
  else
    return strdup(REGISTER_TABLE_8BIT[regCode]);
}

void insert_instruction(InstructionNode *root, const char *bitPattern,
                        const char *mnemonic, int operandCount,
                        const char *operand1Type, const char *operand2Type,
                        int bytes) {
  InstructionNode *current = root;

  while (*bitPattern) {
    if (*bitPattern == '0' || *bitPattern == '1') {
      int index = *bitPattern - '0';
      if (!current->children[index])
        current->children[index] = create_node();
      current = current->children[index];
    } else if (*bitPattern == 'x') {
      // 'x' means "don't care" - we need both parts
      if (!current->children[0])
        current->children[0] = create_node();
      if (!current->children[1])
        current->children[1] = create_node();

      // TODO: Handle this recursively
      InstructionNode *branch = current->children[1];
      char newPattern[256];
      strcpy(newPattern, bitPattern + 1);
      insert_instruction(branch, newPattern, mnemonic, operandCount,
                         operand1Type, operand2Type, bytes);

      current = current->children[0];
    }

    bitPattern++;
  }

  current->isTerminal = true;
  current->instruction.mnemonic = strdup(mnemonic);
  current->instruction.operandCount = operandCount;
  current->instruction.operandTypes[0] =
      operand1Type ? strdup(operand1Type) : NULL;
  current->instruction.operandTypes[1] =
      operand2Type ? strdup(operand2Type) : NULL;
  current->instruction.bytes = bytes;
}

void build_instruction_set(InstructionNode *root) {
  // MOV register to register
  insert_instruction(root, "1000100wrrxxxmmm", MNEMONIC_MOV, 2, OPERAND_REG, OPERAND_REG, 2);

  // MOV immediate to register
  insert_instruction(root, "1011wrrrxxxxxxxx", MNEMONIC_MOV, 2, OPERAND_REG, OPERAND_IMM, 2);

  // MOV memory to register
  insert_instruction(root, "1000101wmmxxxrrr", MNEMONIC_MOV, 2, OPERAND_REG, OPERAND_MEM, 2);

  // MOV register to memory
  insert_instruction(root, "1000100wmmxxxrrr", MNEMONIC_MOV, 2, OPERAND_MEM, OPERAND_REG, 2);

  // TODO: Add more instructions
}

void disassemble_binary(InstructionNode *root, const uint8_t *binary,
                        size_t size) {
  size_t offset = 0;

  while (offset < size) {
    DecodedInstruction *instr =
        decode_instruction(root, &binary[offset], size - offset);

    if (!instr) {
      printf("%04X: DB %02X\n", offset, binary[offset]);
      offset++;
      continue;
    }

    printf("%04X: %s ", offset, instr->mnemonic);

    // Print operands
    for (int i = 0; i < 2 && instr->operands[i][0] != '\0'; i++) {
      printf("%s%s", instr->operands[i], i == 0 ? ", " : "");
    }
    printf("\n");

    // Move to the next instruction
    offset += instr->bytes;
    free(instr);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    printf("Usage: %s <binary_file>\n", argv[0]);
    return 1;
  }

  FILE *file = fopen(argv[1], "rb");
  if (!file) {
    perror("Error opening file");
    return 1;
  }

  fseek(file, 0, SEEK_END);
  size_t size = ftell(file);
  fseek(file, 0, SEEK_SET);

  uint8_t *binary = (uint8_t *)malloc(size);
  fread(binary, 1, size, file);
  fclose(file);

  InstructionNode *root = create_node();
  build_instruction_set(root);

  disassemble_binary(root, binary, size);

  free(binary);

  // TODO: Free the trie

  return 0;
}
