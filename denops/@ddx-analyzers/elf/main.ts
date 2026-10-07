import type { DdxBuffer } from "@shougo/ddx-vim/types";
import {
  type AnalyzeResult,
  BaseAnalyzer,
} from "@shougo/ddx-vim/analyzer";
import { arrayEquals } from "@shougo/ddx-vim/utils";

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
  ): number {
    for (let i = 0; i < 4; i++) {
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
    offset = this.parseSignature(buffer, header, offset);

    // short e_type;

    // short e_machine;

    // int e_version;

    // int e_entry;

    // int e_phoff;

    // int shoff;

    // int e_flags;

    // short e_ehsize;

    // short e_pehtsize;

    // short e_phnum;

    // short e_shetsize;

    // short e_shnum;

    // short e_shstrndx;

    results.push(header);
    return [results, offset];
  }
}
