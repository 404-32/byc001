// SPDX-License-Identifier: Apache-2.0

///|
pub fn PEImage::section_entropies(
  self : Self,
) -> Array[SectionEntropy] raise PeError {
  let results = []
  for section in self.sections {
    results.push({
      section_name: section.name,
      entropy: shannon_entropy(self.data, section.raw_offset, section.raw_size),
      raw_size: section.raw_size,
    })
  }
  results
}

///|
fn shannon_entropy(
  data : Bytes,
  offset : Int32,
  length : Int32,
) -> Double raise PeError {
  if length <= 0 {
    return 0.0
  }
  ensure_range(data, offset, length)
  let counts = Array::make(256, 0)
  for index in 0..<length {
    let byte = data[offset + index].to_int()
    counts[byte] = counts[byte] + 1
  }
  let total = length.to_double()
  let mut entropy = 0.0
  for count in counts {
    if count > 0 {
      let probability = count.to_double() / total
      entropy = entropy - probability * @math.log2(probability)
    }
  }
  entropy
}
