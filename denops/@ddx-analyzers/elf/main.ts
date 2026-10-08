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

    const [, nextOffset] = this.analyzeElfHeader(
      args.buffer,
      results,
      offset,
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

    // char e_ident[16];
    offset = this.parseSignature(buffer, header, offset, 16);

    // short e_type;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_type;",
    );

    // uint16_t e_machine;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_machine;",
    );

    // uint32_t e_version;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // uint32_t e_entry;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // uint32_t e_phoff;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // uint32_t shoff;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // uint32_t e_flags;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint32_t e_version;",
    );

    // uint16_t e_ehsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_ehsize;",
    );

    // uint16_t e_pehtsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_ehsize;",
    );

    // uint16_t e_phnum;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_phnum;",
    );

    // uint16_t e_shetsize;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shetsize;",
    );

    // uint16_t e_shnum;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shnum;",
    );

    // uint16_t e_shstrndx;
    offset = parseLineOffset(
      buffer,
      header,
      offset,
      "uint16_t e_shstrndx;",
    );

    results.push(header);
    return [results, offset];
  }
}
