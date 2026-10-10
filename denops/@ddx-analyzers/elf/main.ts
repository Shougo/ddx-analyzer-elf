import type { DdxBuffer } from "@shougo/ddx-vim/types";
import {
  type AnalyzeResult,
  BaseAnalyzer,
} from "@shougo/ddx-vim/analyzer";
import { parseLineOffset, arrayEquals } from "@shougo/ddx-vim/utils";

export type Params = Record<string, never>;

export class Analyzer extends BaseAnalyzer<Params> {
  override detect(args: {
    buffer: DdxBuffer;
  }): boolean {
    return arrayEquals(args.buffer.getBytes(0, 4), [0x7f, 0x45, 0x4c, 0x46]);
  }

  override parse(args: {
    buffer: DdxBuffer;
  }): AnalyzeResult[] {
    const results: AnalyzeResult[] = [];
    const offset = 0;
    let nextOffset = 0;

    [, nextOffset] = this.analyzeElfHeader(
      args.buffer,
      results,
      offset,
    );

    [, nextOffset] = this.analyzeProgramHeader(
      args.buffer,
      results,
      nextOffset,
    );

    return results;
  }

  override params(): Params {
    return {};
  }

  private parseSignature(
    buffer: DdxBuffer,
    header: AnalyzeResult,
    offset: number,
    size: number,
  ): number {
    for (let i = 0; i < size; i++) {
      header.values.push({
        name: `signature${i}`,
        rawType: "integer",
        value: buffer.getInt8(offset),
        size: 1,
        address: offset,
      });
      offset += 1;
    }
    return offset;
  }

  private analyzeElfHeader(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "ELF_HEADER", values: [] };

    // unsigned char e_ident[16];
    offset = this.parseSignature(buffer, header, offset, 16);

    // Elf64_Half e_type;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_type;",
    );

    // Elf64_Half e_machine;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_machine;",
    );

    // Elf64_Word e_version;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // Elf64_Addr e_entry;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t e_version;",
    );

    // Elf64_Off e_phoff;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t e_version;",
    );

    // Elf64_Off shoff;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t e_version;",
    );

    // Elf64_Word e_flags;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // Elf64_Half e_ehsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_ehsize;",
    );

    // Elf64_Half e_pehtsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_ehsize;",
    );

    // Elf64_Half e_phnum;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_phnum;",
    );

    // Elf64_Half e_shetsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shetsize;",
    );

    // Elf64_Half e_shnum;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shnum;",
    );

    // Elf64_Half e_shstrndx;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shstrndx;",
    );

    results.push(header);
    return [results, offset];
  }

  private analyzeProgramHeader(
    buffer: DdxBuffer,
    results: AnalyzeResult[],
    startOffset: number,
  ): [AnalyzeResult[], number] {
    let offset = startOffset;
    const header: AnalyzeResult = { name: "PROGRAM_HEADER", values: [] };

    // Elf64_Word  p_type;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t p_type;",
    );

    // Elf64_Word  p_flags;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t p_flags;",
    );

    // Elf64_Off   p_offset;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_offset;",
    );

    // Elf64_Addr  p_vaddr;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_vaddr;",
    );

    // Elf64_Addr  p_paddr;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_paddr;",
    );

    // Elf64_Xword p_filesz;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_paddr;",
    );

    // Elf64_Xword p_memsz;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_paddr;",
    );

    // Elf64_Xword p_align;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint64_t p_paddr;",
    );

    results.push(header);
    return [results, offset];
  }
}
