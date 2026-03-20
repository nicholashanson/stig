# Vortex-M
Vortex-M is a full-featured soft-core implementation of the Cortex-M architecture.

It is intended for educational and artistic purposes.

The project supports the core Thumb2 instruction set.

<div align="center">
  <img src="assets/logo.png" width="400"><br>
</div>

## Build and Run
Vortex-M is written in DLang and built using dub:

```
  dub run -c=cortex -- [path_to_elf_file] [soc] [addr] 
```
- [path_to_elf_file] : valid path to an elf file.
- [soc] : one of either "stm32" (for stm32f4X) or "nrf" (for nrf52X).
- [addr] : (optional) run to this address.

